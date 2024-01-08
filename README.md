# Synchronous-Invocation-Serverless-Patterns

## Inovke the function
'''
sam local invoke -e events/event-post-user.json -n env.json

'''


## Verify new record is created
'''
aws dynamodb get-item --table-name ws-serverless-patterns-users-Users --key '{"userid": {"S": "<userid-from-response>"}}'
'''