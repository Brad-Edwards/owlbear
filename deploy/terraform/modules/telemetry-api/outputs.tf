output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = aws_apigatewayv2_api.telemetry.api_endpoint
}

output "api_key" {
  description = "API key for authentication"
  value       = random_password.api_key.result
  sensitive   = true
}

output "api_key_ssm_name" {
  description = "SSM parameter name for the API key"
  value       = aws_ssm_parameter.api_key.name
}

output "events_table_name" {
  description = "DynamoDB events table name"
  value       = aws_dynamodb_table.events.name
}

output "heartbeats_table_name" {
  description = "DynamoDB heartbeats table name"
  value       = aws_dynamodb_table.heartbeats.name
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.telemetry.function_name
}
