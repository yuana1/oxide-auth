#![cfg(feature = "actix-frontend")]

mod support;
extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate oxide_auth;
extern crate url;

use std::sync::Arc;

use actix::{Actor, Addr, Handler, MailboxError, Message};
use actix::dev::ToEnvelope;
use actix_web::{server, App, HttpRequest, HttpResponse, Error as AWError};
use actix_web::http::Method;
use futures::Future;

use oxide_auth::frontends::actix::*;
use oxide_auth::frontends::actix::message::*;
use oxide_auth::code_grant::frontend::{OAuthError, OwnerAuthorization};
use oxide_auth::primitives::prelude::*;
use support::actix::dummy_client;
use support::open_in_browser;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

trait AbstractAddr<M: Message> {
    fn send(&self, message: M) -> Box<Future<Item=M::Result, Error=MailboxError>>;
}

impl<A, M> AbstractAddr<M> for Addr<A> 
where
    A: Actor + Handler<M>, 
    M: Message + Send + 'static,
    A::Context: ToEnvelope<A, M>,
    M::Result: Send,
{
    fn send(&self, message: M) -> Box<Future<Item=M::Result, Error=MailboxError>> {
        Box::new(self.send(message))
    }
}

trait AbstractEndpoint {
    fn access_token(&self) -> &AbstractAddr<AccessToken>;
    fn authorization_code(&self) -> &AbstractAddr<AuthorizationCode>;
    fn resource_guard(&self) -> &AbstractAddr<Guard>;
}

impl<T> AbstractEndpoint for T 
    where T: AbstractAddr<AccessToken> + AbstractAddr<AuthorizationCode> + AbstractAddr<Guard> 
{
    fn access_token(&self) -> &AbstractAddr<AccessToken> { self }
    fn authorization_code(&self) -> &AbstractAddr<AuthorizationCode> { self }
    fn resource_guard(&self) -> &AbstractAddr<Guard> { self }
}

/// Example of a main function of a rouille server supporting oauth.
pub fn main() {
    let sys = actix::System::new("HttpServerClient");

    let mut clients  = ClientMap::new();
    // Register a dummy client instance
    let client = Client::public("LocalClient", // Client id
        "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
        "default".parse().unwrap()); // Allowed client scope
    clients.register_client(client);

    let authorizer = Storage::new(RandomGenerator::new(16));
    let issuer = TokenSigner::ephemeral();
    let scopes = vec!["default".parse().unwrap()].into_boxed_slice();

    // Emulate static initialization for complex type
    let scopes: &'static _ = Box::leak(scopes);

    let endpoint: Addr<_> = CodeGrantEndpoint::new((clients, authorizer, issuer))
        .with_authorization(|&mut (ref client, ref mut authorizer, _)| {
            AuthorizationFlow::new(client, authorizer)
        })
        .with_grant(|&mut (ref client, ref mut authorizer, ref mut issuer)| {
            GrantFlow::new(client, authorizer, issuer)
        })
        .with_guard(move |&mut (_, _, ref mut issuer)| {
            AccessFlow::new(issuer, scopes)
        })
        .start();

    let boxed: Arc<AbstractEndpoint + Send + Sync> = Arc::new(endpoint);

    // Create the main server instance
    server::new(
        move || App::with_state(boxed.clone())
            .resource("/authorize", |r| {
                r.get().f(|req: &HttpRequest<_>| {
                    let endpoint = req.state().clone();
                    Box::new(req.oauth2()
                        .authorization_code(handle_get)
                        .and_then(move |request| endpoint.authorization_code()
                            .send(request)
                            .map_err(|_| OAuthError::InvalidRequest)
                            .and_then(|result| result.map(Into::into))
                        )
                        .or_else(|err| Ok(ResolvedResponse::response_or_error(err).actix_response()))
                    ) as Box<Future<Item = HttpResponse, Error = AWError>>
                });
                r.post().f(|req: &HttpRequest<_>| {
                    let endpoint = req.state().clone();
                    let denied = req.query_string().contains("deny");
                    Box::new(req.oauth2()
                        .authorization_code(move |grant| handle_post(denied, grant))
                        .and_then(move |request| endpoint.authorization_code()
                            .send(request)
                            .map_err(|_| OAuthError::InvalidRequest)
                            .and_then(|result| result.map(Into::into))
                        )
                        .or_else(|err| Ok(ResolvedResponse::response_or_error(err).actix_response()))
                    ) as Box<Future<Item = HttpResponse, Error = AWError>>
                });
            })
            .resource("/token", |r| r.method(Method::POST).f(|req: &HttpRequest<_>| {
                let endpoint = req.state().clone();
                Box::new(req.oauth2()
                    .access_token()
                    .and_then(move |request| endpoint.access_token()
                        .send(request)
                        .map_err(|_| OAuthError::InvalidRequest)
                        .and_then(|result| result.map(Into::into))
                    )
                    .or_else(|err| Ok(ResolvedResponse::response_or_error(err).actix_response()))
                ) as Box<Future<Item = HttpResponse, Error = AWError>>
            }))
            .resource("/", |r| r.method(Method::GET).f(|req: &HttpRequest<_>| {
                let endpoint = req.state().clone();
                Box::new(req.oauth2()
                    .guard()
                    .and_then(move |request| endpoint.resource_guard()
                        .send(request)
                        .map_err(|_| OAuthError::InvalidRequest)
                        .and_then(|result| result)
                    ).map(|()|
                        HttpResponse::Ok()
                            .content_type("text/plain")
                            .body("Hello world!")
                    ).or_else(|error| {
                        Ok(ResolvedResponse::response_or_error(error)
                            .actix_response()
                            .into_builder()
                            .content_type("text/html")
                            .body(DENY_TEXT))
                    })
                ) as Box<Future<Item = HttpResponse, Error = AWError>>
            }))
        )
        .bind("localhost:8020")
        .expect("Failed to bind to socket")
        .start();

    server::new(|| App::new().handler("/endpoint", dummy_client))
        .bind("localhost:8021")
        .expect("Failed to start dummy client")
        .start();

    actix::System::current().arbiter()
        .do_send(actix::msgs::Execute::new(
            || -> Result<(), ()> { Ok(open_in_browser()) }));
    let _ = sys.run();
}

/// A simple implementation of the first part of an authentication handler. This will
/// display a page to the user asking for his permission to proceed. The submitted form
/// will then trigger the other authorization handler which actually completes the flow.
fn handle_get(grant: &PreGrant) -> OwnerAuthorization<ResolvedResponse> {
    let text = format!(
        "<html>'{}' (at {}) is requesting permission for '{}'
        <form method=\"post\">
            <input type=\"submit\" value=\"Accept\" formaction=\"authorize?response_type=code&client_id={}\">
            <input type=\"submit\" value=\"Deny\" formaction=\"authorize?response_type=code&client_id={}&deny=1\">
        </form>
        </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
    let response = ResolvedResponse::html(&text);
    OwnerAuthorization::InProgress(response)
}

/// Handle form submission by a user, completing the authorization flow. The resource owner
/// either accepted or denied the request.
fn handle_post(denied: bool, _: &PreGrant) -> OwnerAuthorization<ResolvedResponse> {
    // No real user authentication is done here, in production you SHOULD use session keys or equivalent
    if denied {
        OwnerAuthorization::Denied
    } else {
        OwnerAuthorization::Authorized("dummy user".to_string())
    }
}
