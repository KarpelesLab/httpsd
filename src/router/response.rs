//! [`IntoResponse`]: coercions that let route handlers return plain values.

use std::borrow::Cow;

use crate::proto::{Response, StatusCode};

/// A value that can be turned into a [`Response`].
///
/// This is what lets a [`RouteHandler`](super::RouteHandler) return a bare
/// `&str`, `String`, `Vec<u8>`, [`StatusCode`], a `(StatusCode, T)` pair, an
/// `Option<T>`, or a `Result<T, E>` instead of always building a full
/// [`Response`]. Implement it for your own types to return them directly.
pub trait IntoResponse {
    /// Consume `self` and produce the response to send.
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

/// An empty `200 OK`.
impl IntoResponse for () {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK)
    }
}

/// A bare status with an empty body.
impl IntoResponse for StatusCode {
    fn into_response(self) -> Response {
        Response::new(self)
    }
}

impl IntoResponse for &str {
    fn into_response(self) -> Response {
        Response::text(self.to_owned())
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        Response::text(self)
    }
}

impl IntoResponse for Cow<'_, str> {
    fn into_response(self) -> Response {
        Response::text(self.into_owned())
    }
}

impl IntoResponse for Vec<u8> {
    fn into_response(self) -> Response {
        Response::new(StatusCode::OK)
            .header("Content-Type", "application/octet-stream")
            .body(self)
    }
}

impl IntoResponse for &[u8] {
    fn into_response(self) -> Response {
        self.to_vec().into_response()
    }
}

/// `Some` becomes the inner response; `None` becomes `404 Not Found`.
impl<T: IntoResponse> IntoResponse for Option<T> {
    fn into_response(self) -> Response {
        match self {
            Some(value) => value.into_response(),
            None => Response::status(StatusCode::NOT_FOUND),
        }
    }
}

/// `Ok` and `Err` are each coerced — so `?` works inside a handler as long as
/// the error type is [`IntoResponse`].
impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Response {
        match self {
            Ok(value) => value.into_response(),
            Err(err) => err.into_response(),
        }
    }
}

/// Override the status of an inner response, e.g. `(StatusCode::CREATED, body)`.
impl<T: IntoResponse> IntoResponse for (StatusCode, T) {
    fn into_response(self) -> Response {
        let (status, inner) = self;
        inner.into_response().with_status(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_is_text_plain_200() {
        let resp = "hi".into_response();
        assert_eq!(resp.status_code(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(resp.body_ref().as_bytes(), b"hi");
    }

    #[test]
    fn status_tuple_overrides_status_keeps_body() {
        let resp = (StatusCode::CREATED, "made").into_response();
        assert_eq!(resp.status_code(), StatusCode::CREATED);
        assert_eq!(resp.body_ref().as_bytes(), b"made");
    }

    #[test]
    fn result_coerces_both_arms() {
        let ok: Result<&str, StatusCode> = Ok("good");
        assert_eq!(ok.into_response().status_code(), StatusCode::OK);
        let err: Result<&str, StatusCode> = Err(StatusCode::BAD_REQUEST);
        assert_eq!(err.into_response().status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn option_none_is_404() {
        let none: Option<&str> = None;
        assert_eq!(none.into_response().status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn bytes_are_octet_stream() {
        let resp = vec![1u8, 2, 3].into_response();
        assert_eq!(
            resp.headers().get("content-type"),
            Some("application/octet-stream")
        );
    }
}
