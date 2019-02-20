use std::str::from_utf8;
use std::marker::PhantomData;

use code_grant::accesstoken::{
    access_token,
    Error as TokenError,
    Extension,
    Endpoint as TokenEndpoint,
    Request as TokenRequest};

use super::*;

/// Offers access tokens to authenticated third parties.
///
/// After having received an authorization code from the resource owner, a client must
/// directly contact the OAuth endpoint–authenticating itself–to receive the access
/// token. The token is then used as authorization in requests to the resource. This
/// request MUST be protected by TLS.
pub struct AccessTokenFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedToken<E, R>,
}

struct WrappedToken<E: Endpoint<R>, R: WebRequest> {
    inner: E, 
    extension_fallback: (),
    r_type: PhantomData<R>, 
}

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The query in the url.
    body: Cow<'a, QueryParameter + 'static>,

    /// The authorization tuple
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<Option<R::Error>>,
}

struct Authorization(String, Vec<u8>);

impl<E, R> AccessTokenFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    /// Check that the endpoint supports the necessary operations for handling requests.
    ///
    /// Binds the endpoint to a particular type of request that it supports, for many
    /// implementations this is probably single type anyways.
    ///
    /// ## Panics
    ///
    /// Indirectly `execute` may panic when this flow is instantiated with an inconsistent
    /// endpoint, for details see the documentation of `Endpoint` and `execute`. For 
    /// consistent endpoints, the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.authorizer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.issuer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(AccessTokenFlow {
            endpoint: WrappedToken {
                inner: endpoint,
                extension_fallback: (),
                r_type: PhantomData
            },
        })
    }

    /// Use the checked endpoint to check for authorization for a resource.
    ///
    /// ## Panics
    ///
    /// When the registrar, authorizer, or issuer returned by the endpoint is suddenly 
    /// `None` when previously it was `Some(_)`.
    pub fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let issued = access_token(
            &mut self.endpoint,
            &WrappedRequest::new(&mut request));

        let token = match issued {
            Err(error) => return token_error(&mut self.endpoint.inner, &mut request, error),
            Ok(token) => token,
        };

        let mut response = self.endpoint.inner.response(&mut request, InnerTemplate::Ok.into())?;
        response.body_json(&token.to_json())
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

fn token_error<E: Endpoint<R>, R: WebRequest>(endpoint: &mut E, request: &mut R, error: TokenError)
    -> Result<R::Response, E::Error>
{
    Ok(match error {
        TokenError::Invalid(mut json) => {
            let mut response = endpoint.response(request, InnerTemplate::BadRequest {
                access_token_error: Some(json.description()),
            }.into())?;
            response.client_error()
                .map_err(|err| endpoint.web_error(err))?;
            response.body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        },
        TokenError::Unauthorized(mut json, scheme) =>{
            let mut response = endpoint.response(request, InnerTemplate::Unauthorized {
                error: None,
                access_token_error: Some(json.description()),
            }.into())?;
            response.unauthorized(&scheme)
                .map_err(|err| endpoint.web_error(err))?;
            response.body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        },
        TokenError::Primitive(_) => {
            // FIXME: give the context for restoration.
            return Err(endpoint.error(OAuthError::PrimitiveError))
        },
    })
}

impl<E: Endpoint<R>, R: WebRequest> TokenEndpoint for WrappedToken<E, R> {
    fn registrar(&self) -> &Registrar {
        self.inner.registrar().unwrap()
    }

    fn authorizer(&mut self) -> &mut Authorizer {
        self.inner.authorizer_mut().unwrap()
    }

    fn issuer(&mut self) -> &mut Issuer {
        self.inner.issuer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut Extension {
        self.inner.extension()
            .and_then(|ext| ext.access_token())
            .unwrap_or(&mut self.extension_fallback)
    }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R) -> Self {
        Self::new_or_fail(request)
            .unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R) -> Result<Self, Option<R::Error>> {
        // If there is a header, it must parse correctly.
        let authorization = match request.authheader() {
            Err(err) => return Err(Some(err)),
            Ok(Some(header)) => Self::parse_header(header).map(Some)?,
            Ok(None) => None,
        };

        Ok(WrappedRequest {
            request: PhantomData,
            body: request.query()?,
            authorization,
            error: None,
        })
    }

    fn from_err(err: Option<R::Error>) -> Self {
        WrappedRequest {
            request: PhantomData,
            body: Cow::Owned(Default::default()),
            authorization: None,
            error: Some(err),
        }
    }

    fn parse_header(header: Cow<str>) -> Result<Authorization, Option<R::Error>> {
        let authorization = {
            if !header.starts_with("Basic ") {
                return Err(None)
            }

            let combined = match base64::decode(&header[6..]) {
                Err(_) => return Err(None),
                Ok(vec) => vec,
            };

            let mut split = combined.splitn(2, |&c| c == b':');
            let client_bin = match split.next() {
                None => return Err(None),
                Some(client) => client,
            };
            let passwd = match split.next() {
                None => return Err(None),
                Some(passwd64) => passwd64,
            };

            let client = match from_utf8(client_bin) {
                Err(_) => return Err(None),
                Ok(client) => client,
            };

            Authorization(client.to_string(), passwd.to_vec())
        };

        Ok(authorization)
    }
}

impl<'a, R: WebRequest> TokenRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn code(&self) -> Option<Cow<str>> {
        self.body.unique_value("code")
    }

    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
        self.authorization.as_ref()
            .map(|auth| (auth.0.as_str().into(), auth.1.as_slice().into()))
    }

    fn client_id(&self) -> Option<Cow<str>> {
        self.body.unique_value("client_id")
    }

    fn redirect_uri(&self) -> Option<Cow<str>> {
        self.body.unique_value("redirect_uri")
    }

    fn grant_type(&self) -> Option<Cow<str>> {
        self.body.unique_value("grant_type")
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.body.unique_value(key)
    }
}
