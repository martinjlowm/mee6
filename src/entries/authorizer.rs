use aws_lambda_events::event::apigw::{
    ApiGatewayCustomAuthorizerPolicy, ApiGatewayCustomAuthorizerRequestTypeRequest,
    ApiGatewayCustomAuthorizerResponse, IamPolicyStatement,
};
use lambda::{Context, handler_fn};
use std::{collections::HashMap, env};
use serde_json::Value;

#[macro_use]
extern crate lazy_static;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

lazy_static! {
    static ref CONTEXT: HashMap<String, Value> = HashMap::new();
    static ref SLACK_SIGNATURE: String = env::var("SLACK_SIGNATURE").unwrap();
}

async fn handler(
    event: ApiGatewayCustomAuthorizerRequestTypeRequest,
    _: Context,
) -> Result<ApiGatewayCustomAuthorizerResponse, Error> {
    let is_trusted = match event.headers.get("X-Slack-Signature") {
        Some(signature) => *signature == *SLACK_SIGNATURE,
        _ => false,
    };

    if !is_trusted {
        return Err("Unauthorized".into());
    }

    let arn = event.method_arn.unwrap();
    let (region, account_id, api_gateway_arn) = match arn.split(":").collect::<Vec<&str>>().as_slice() {
        &[_, _, _, region, account_id, api_gateway_arn] => (region, account_id, api_gateway_arn),
        _ => unreachable!(),
    };

    let api = match api_gateway_arn.split("/").collect::<Vec<&str>>().as_slice() {
        &[api] => api,
        _ => unreachable!(),
    };

    Ok(ApiGatewayCustomAuthorizerResponse {
        principal_id: Some("MEE6".into()),
        policy_document: ApiGatewayCustomAuthorizerPolicy {
            version: Some("2012-10-17".into()),
            statement: vec![IamPolicyStatement {
                action: vec!["execute-api:Invoke".into()],
                resource: vec![format!("arn:aws:execute-api:{region}:{account_id}:{api}/*", region = region, account_id = account_id, api = api)],
                effect: Some("Allow".into()),
            }],
        },
        usage_identifier_key: Some("slack-api-key-lulz".into()),
        context: CONTEXT.to_owned(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = handler_fn(handler);
    lambda::run(func).await?;
    Ok(())
}
