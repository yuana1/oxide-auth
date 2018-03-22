extern crate hyper;
extern crate mime;
extern crate futures;
extern crate gotham;
extern crate serde_urlencoded;


use code_grant::frontend::{WebRequest, WebResponse};
pub use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow};
pub use code_grant::frontend::{OwnerAuthorization, OAuthError, OwnerAuthorizer, QueryParameter, SingleValueQuery, AuthorizationResult};
pub use code_grant::prelude::*;

use self::hyper::{StatusCode, Request, Response, Method, Uri, Body};
use self::hyper::header::{Authorization, ContentLength, ContentType, Location};
use gotham::state::{FromState, State};
use gotham::middleware::Middleware;
use gotham::handler::HandlerFuture;

use url::Url;
use self::futures::{Async, Poll, Stream};
pub use self::futures::{Future, future};

use std::borrow::Cow;
use std::collections::HashMap;
use gotham::handler::IntoHandlerError;

#[derive(StateData)]
pub struct OAuthRequest(Request);

#[derive(Clone, NewMiddleware)]
pub struct OAuthRequestMiddleware;
impl Middleware for OAuthRequestMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Box<HandlerFuture>
    where
        Chain: FnOnce(State) -> Box<HandlerFuture> + 'static,
    {
        let f = state.take::<Body>().concat2().then(move |chunk| {
            let method = state.borrow::<Method>().clone();
            let uri = state.borrow::<Uri>().clone();

            let mut request = Request::new(method.clone(), uri.clone());
            let body = chunk.unwrap().to_vec();
            request.set_body(body.clone());

            let mut request2 = Request::new(method, uri);
            request2.set_body(body);

            state.put(OAuthRequest(request));
            state.put(request2.body());

            chain(state)
        });

        Box::new(f)
    }
}

pub struct ResolvedRequest {
    request: Request,
    authorization: Result<Option<String>, ()>,
    query: Option<HashMap<String, String>>,
    body: Option<HashMap<String, String>>,
}

impl OAuthRequest {
    pub fn authorization_code(self, state: &State) -> AuthorizationCodeRequest {
        let OAuthRequest(request) = self;

        AuthorizationCodeRequest {
            request: Some(request),
            state: state,
        }
    }

    pub fn access_token(self, body: Body) -> GrantRequest {
        let OAuthRequest(request) = self;

        GrantRequest {
            request: Some(request),
            body: Some(body),
        }
    }

    pub fn guard(self) -> GuardRequest {
        let OAuthRequest(request) = self;

        GuardRequest {
            request: Some(request),
        }
    }
}

pub struct AuthorizationCodeRequest<'a> {
    request: Option<Request>,
    state: &'a State,
}

pub struct GrantRequest {
    request: Option<Request>,
    body: Option<Body>,
}

pub struct GuardRequest {
    request: Option<Request>,
}

pub struct ReadyAuthorizationCodeRequest<'a> {
    request: ResolvedRequest,
    state: &'a State,
}
pub struct ReadyGrantRequest(ResolvedRequest);
pub struct ReadyGuardRequest(ResolvedRequest);

impl WebRequest for ResolvedRequest {
    type Error = OAuthError;
    type Response = Response;

     fn query(&mut self) -> Result<QueryParameter, ()> {
         self.query.as_ref().map(|query| QueryParameter::SingleValue(
             SingleValueQuery::StringValue(Cow::Borrowed(query))))
             .ok_or(())
     }

     fn urlbody(&mut self) -> Result<QueryParameter, ()> {
         self.body.as_ref().map(|body| QueryParameter::SingleValue(
             SingleValueQuery::StringValue(Cow::Borrowed(body))))
             .ok_or(())
     }

     fn authheader(&mut self) -> Result<Option<Cow<str>>, ()>{
         match &self.authorization {
             &Ok(Some(ref string)) => Ok(Some(Cow::Borrowed(string))),
             &Ok(None) => Ok(None),
             &Err(_) => Err(())
         }
     }
}

impl WebResponse for Response {
    type Error = OAuthError;

    fn redirect(url: Url) -> Result<Self, Self::Error> {
        let response = Response::new()
            .with_header(Location::new(url.into_string()))
            .with_status(StatusCode::Found);

        Ok(response)
    }

    fn text(text: &str) -> Result<Self, Self::Error> {
        let response = Response::new()
            .with_header(ContentLength(text.len() as u64))
            .with_header(ContentType(mime::TEXT_PLAIN))
            .with_status(StatusCode::Ok)
            .with_body(text.to_owned());

        Ok(response)
    }

    fn json(data: &str) -> Result<Self, Self::Error> {
        let response = Response::new()
            .with_header(ContentLength(data.len() as u64))
            .with_header(ContentType(mime::APPLICATION_JSON))
            .with_status(StatusCode::Ok)
            .with_body(data.to_owned());

        Ok(response)
    }

    fn as_client_error(mut self) -> Result<Self, Self::Error> {
        self.set_status(StatusCode::BadRequest);
        Ok(self)
    }

    /// Set the response status to 401
    fn as_unauthorized(mut self) -> Result<Self, Self::Error> {
        self.set_status(StatusCode::Unauthorized);
        Ok(self)
    }

    /// Add an `WWW-Authenticate` header
    fn with_authorization(mut self, kind: &str) -> Result<Self, Self::Error> {
        self.headers_mut().set_raw("WWW-Authenticate", vec![kind.as_bytes().to_vec()]);
        Ok(self)
    }

}

impl ResolvedRequest {
    fn headers_only(request: Request) -> Self {
        let authorization = match request.headers().get::<Authorization<String>>() {
            None => Ok(None),
            Some(header) => Ok(Some(format!("{}", header)))
        };

        let mut query = None;
        if let Some(query_string) = request.query() {
            query = serde_urlencoded::from_str::<HashMap<String, String>>(query_string)
                .map(|v| {
                  Some(v)
                })
                .unwrap();
        }

        ResolvedRequest {
            request: request,
            authorization: authorization,
            query: query,
            body: None,
        }
    }

    fn with_body(request: Request, body: HashMap<String, String>) -> Self {
        let mut resolved = Self::headers_only(request);
        resolved.body = Some(body);
        resolved
    }
}

struct ResolvedOwnerAuthorization<'a, A> {
    handler: A,
    state: &'a State,
}

impl<'a, A> OwnerAuthorizer<ResolvedRequest> for ResolvedOwnerAuthorization<'a, A>
where A: Fn(&Request, &State, &PreGrant) -> OwnerAuthorization<Response> {
    fn check_authorization(self, request: ResolvedRequest, grant: &PreGrant) -> OwnerAuthorization<Response> {
        (self.handler)(&request.request, self.state, grant)
    }
}

impl<'a> Future for AuthorizationCodeRequest<'a> {
    type Item = ReadyAuthorizationCodeRequest<'a>;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyAuthorizationCodeRequest {request: resolved, state: self.state}))
    }
}


impl Future for GrantRequest {
    type Item = ReadyGrantRequest;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body.take().unwrap().poll() {
            Ok(Async::Ready(body)) => {
                let vec = body.unwrap().to_vec();
                let body_string = String::from_utf8(vec).unwrap();
                let body_decoded: HashMap<String, String> = serde_urlencoded::from_str(body_string.as_str())
                  .map_err(|_| ()).unwrap();
                let resolved = ResolvedRequest::with_body(self.request.take().unwrap(), body_decoded);
                Ok(Async::Ready(ReadyGrantRequest(resolved)))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),

            // Not a valid url encoded body
            Err(_) => Err(OAuthError::AccessDenied),
        }
    }
}

impl Future for GuardRequest {
    type Item = ReadyGuardRequest;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyGuardRequest(resolved)))
    }
}

impl<'a> ReadyAuthorizationCodeRequest<'a> {
    pub fn handle<A>(self, flow: AuthorizationFlow, authorizer: A)-> Result<Response, OAuthError>
    where A: Fn(&Request, &State, &PreGrant) -> OwnerAuthorization<Response> {
        flow.handle(self.request).complete(ResolvedOwnerAuthorization { handler: authorizer, state: self.state })
    }
}

impl ReadyGrantRequest {
    pub fn handle(self, flow: GrantFlow) -> Result<Response, OAuthError> {
        flow.handle(self.0)
    }
}

impl ReadyGuardRequest {
    pub fn handle(self, flow: AccessFlow) -> Result<(), OAuthError> {
        flow.handle(self.0)
    }
}