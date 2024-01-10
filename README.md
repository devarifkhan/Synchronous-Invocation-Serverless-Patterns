# Serverless Patterns Synchronous Invocation
![Application Component: Users Service](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch.svg)
## Create Project with SAM
#### Run `sam init` and follow the prompts to create a new serverless application :
    sam init --name "ws-serverless-patterns" --location "https://ws-assets-prod-iad-r-iad-ed304a55c2ca1aee.s3.us-east-1.amazonaws.com/76bc5278-3f38-46e8-b306-f0bfda551f5a/module2/sam-python/sam-cookiecutter-2023-11-03.zip"
  
  #### At each prompt, accept the default values.
  

    project_name [ws-serverless-patterns]:
    runtime [python3.9]:
    architechtures [default]:
  #### Delete default `samconfig.toml` file
  

    rm samconfig.toml
   
   #### Navigate to `users` directory

    cd ./users

## Create a python Virtual environment

#### List default dependencies

    pip freeze
 #### Create a new Virtual environment

    python -m venv venv
  
#### activate the virtual environment

    source venv/bin/activate
#### List dependencies again:

```bash
pip freeze
```
    

## Create Data Store DynamoDB
![Dynamodb table](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch-data.svg)
#### To Create User Table
open the `ws-serverless-patterns/users` directory, then open `template.yaml` and paste in the following template to create a DynamoDB table:
> SAM template.yaml v1 - Data store
```yml
# The SAM template starts with a boilerplate header to set the template version used during the transformation from SAM to CloudFormation.

AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v1 - Data store

#he `Globals:` section is commented out because it is currently unused. The transformation will fail with an empty globals section. In the near future, you will set the Python version to use across all resources in the globals section
# Globals:

#The `Resources:` section is where the fun starts. This is where you define infrastructure resources in your project.
# Each resource has a _name_ in the template. You pick it. Think of this like a variable name, or nickname.
Resources:
  UsersTable:
  #Every resource also has a has a `Type:` attribute. There are CloudFormation and SAM types. CloudFormation types have every possible configuration option available, whereas SAM types are more concise, with only frequently used properties.
      Type: AWS::DynamoDB::Table
      #Speaking of _properties_, the `Properties:` section contains information needed to create the resource.
      Properties:
      #The first property, **TableName**, is created with a dynamic substitution by a CloudFormation _intrinsic function_.
      #The !Sub function will substitute in the stackname as a prefix for the table name, so that it will be unique within your account.
      #Intrinsics, as they are called, are built-in functions to assign values to properties that are not available until runtime.
        TableName: !Sub  ${AWS::StackName}-Users 
#**AttributeDefinitions** creates a userid attribute that is used in the **KeySchema** to be the primary key / partition id.
        AttributeDefinitions:
          - AttributeName: userid
            AttributeType: S
        KeySchema:
          - AttributeName: userid
            KeyType: HASH
            # And, **BillingMode** sets up the billing option for the table, as you might expect.
        BillingMode: PAY_PER_REQUEST

the **Outputs:** section prints key, description, and values to the terminal. These provide confirmation that resources were created, and are especially useful to see dynamically generated data, such as IDs, ARNs, and dynamic names created during the deploy step
Outputs:
  UsersTable:
      Description: DynamoDB Users table
      Value: !Ref UsersTable

```
#### build the project

    sam build

#### Deploy the project

After the build completes successfully, deploy the project :

```bash
sam deploy --guided --stack-name ws-serverless-patterns-users
```

 In this case, SAM will show the value that results from the !Sub function replacing ${AWS::StackName} to create the **TableName**.

 Every resource has a unique **Amazon Resource Name** or **ARN**. Can you find the **ARN** for the table you created?

Look in the Overview, then General Information tab... expand...
Look in the Overview, then General Information tab... expand Additional Info... look for a string like this:

```
arn:aws:dynamodb:us-west-1:123456789012:table/serverless-workshop-Users
```


## Add Business Logic
![Business Logic](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch-applogic.svg)

#### Add Lambda Function to template
 Copy and paste the following configuration with a Lambda function into template.yaml:
> SAM template.yaml v2 - Lambda Function

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns - v2 Lambda function

#There is now a [Globals section](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-template-anatomy-globals.html) so that all functions will have the same runtime configuration, unless overridden by individual function properties.
Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
    #By convention, the name of the Lambda event handler function is **lambda_handler**. The handler property is the path to the Users.py file, but the suffix ".py" has been replaced with the function handler name ("lambda_handler"). This will become clearer when you later create the Lambda function.
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      #The Environment property creates a USERS_TABLE environment variable for the UsersTable resource name. This value will be available to the Lambda function, so that hard-coding database table name is not necessary. This is good because the full name is not known until the infrastructure stack is deployed.
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"


Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable
#You will need to refer to the function outside of this template, so, the [Outputs section](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-template-anatomy.html) adds an output to show the full unique name of the deployed UsersFunction:
  UsersFunction:
    Description: "Lambda function used to perform actions on the users data"
    Value: !Ref UsersFunction

```

#### Create lambda Function
#### Open `src/api/users.py` and replace the default contents with the following code:

```yaml
import json
import uuid
import os
import boto3
from datetime import datetime

# Prepare DynamoDB client
# Get DynamoDB table name from the environment variable and configuring DynamoDB client
USERS_TABLE = os.getenv('USERS_TABLE', None)
dynamodb = boto3.resource('dynamodb')
ddbTable = dynamodb.Table(USERS_TABLE)

def lambda_handler(event, context):
    route_key = f"{event['httpMethod']} {event['resource']}"

    # Set default response, override with data from DynamoDB if any
    # Setting default response to be used in case the requested route does not match implemented ones
    response_body = {'Message': 'Unsupported route'}
    status_code = 400
    headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
        }

    try:
        # Get a list of all Users
        # Returning all records in the database. In most scenarios, you would add pagination or other ways to limit number of items requested from DynamoDB and returned to the requestor as scanning entire table is impractical and costly
        if route_key == 'GET /users':
            ddb_response = ddbTable.scan(Select='ALL_ATTRIBUTES')
            # return list of items instead of full DynamoDB response
            response_body = ddb_response['Items']
            status_code = 200

        # CRUD operations for a single User
       
        # Read a user by ID
        # Get data from DynamoDB for a single user (ID passed as a path parameter), return user data as a response body. Return empty response body if the user does not exist
        if route_key == 'GET /users/{userid}':
            # get data from the database
            ddb_response = ddbTable.get_item(
                Key={'userid': event['pathParameters']['userid']}
            )
            # return single item instead of full DynamoDB response
            if 'Item' in ddb_response:
                response_body = ddb_response['Item']
            else:
                response_body = {}
            status_code = 200
        
        # Delete a user by ID
       # Delete user data in DynamoDB. Use user ID passed as a path parameter. Return empty response body
        if route_key == 'DELETE /users/{userid}':
            # delete item in the database
            ddbTable.delete_item(
                Key={'userid': event['pathParameters']['userid']}
            )
            response_body = {}
            status_code = 200
        
        # Create a new user 
        # Create/update user data in DynamoDB. Use request payload data without transformations. Inject current date/time into the request. Add unique user ID if it isn't present in the request. Return modified request data as a response body
        if route_key == 'POST /users':
            request_json = json.loads(event['body'])
            request_json['timestamp'] = datetime.now().isoformat()
            # generate unique id if it isn't present in the request
            if 'userid' not in request_json:
                request_json['userid'] = str(uuid.uuid1())
            # update the database
            ddbTable.put_item(
                Item=request_json
            )
            response_body = request_json
            status_code = 200

        # Update a specific user by ID
        # Update user data in DynamoDB. Use request path parameters to identify user and override user ID in the request payload. Inject current date/time into the request. Return modified request data as a response body
        if route_key == 'PUT /users/{userid}':
            # update item in the database
            request_json = json.loads(event['body'])
            request_json['timestamp'] = datetime.now().isoformat()
            request_json['userid'] = event['pathParameters']['userid']
            # update the database
            ddbTable.put_item(
                Item=request_json
            )
            response_body = request_json
            status_code = 200
    except Exception as err:
    # Error handling code. Return error message in the response code and log it to CLoudWatch logs by printing error data into stdout
        status_code = 400
        response_body = {'Error:': str(err)}
        print(str(err))
        # Return response data in a format expected by the API Gateway
    return {
        'statusCode': status_code,
        'body': json.dumps(response_body),
        'headers': headers
    }


```
#### Update the Python dependency list

Open `ws-serverless-patterns/users/requirements.txt` and copy/paste in the following dependencies:

```python
datetime
boto3
python-jose
```
####  Build and deploy

In the command line run the build and deploy commands:

```bash
sam build && sam deploy
```

## Test Locally

![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/test-cycle-491854279.jpg)
#### Set up test environment & event
#### Set environment variables
Create a new file called `env.json` in the `users` directory of the project. When Lambda functions are run locally with SAM local, environment variables will be created from the values in this file.
 Paste the following JSON into `env.json`, substituting in the **UsersTable value** from the previous deploy output:
```json
{
    "UsersFunction": {
        "USERS_TABLE": "<UsersTable output value from previous deploy>"
    }
}
|  |  |
|--|--|
|  |  |


```

> UsersTable name will be based on the name of the **CloudFormation stack**. That name will be in the previous deploy output.



#### Set up a test event
An event is **always** needed to invoke a Lambda function.you will use event files stored in the `/events` directory.Open `event-post-user.json` in the editor.
 It should look like the following JSON snippet and will test one resource path. Events can be created to test each resource and path in the application. There are additional events in the folder that will be used later for unit tests.

```json
{
    "resource": "/users",
    "path": "/users",
    "httpMethod": "POST",
    "headers": null,
    "multiValueHeaders": null,
    "queryStringParameters": null,
    "multiValueQueryStringParameters": null,
    "pathParameters": null,
    "stageVariables": null,
    "requestContext": {
        "requestId": "be946131-30c4-4396-9c29-f25f8caa91dc"
    },
    "body": "{\"name\":\"John Doe\"}",
    "isBase64Encoded": false
}
```
#### Invoke the function


Now that the environment and event are ready, invoke the function locally to verify it:

```bash
sam local invoke -e events/event-post-user.json -n env.json
```

The first time this runs, SAM will build a container image. This will take a minute or so. Subsequent runs will be immediate.

You should eventually see a response, similar to the following, with a 200 status and data for a new User record:

```json
{"statusCode": 200, 
 "body": "{\"name\": \"John Doe\", 
   \"timestamp\": \"2022-06-21T20:25:16.342221\", 
   \"userid\": \"430a7594-f1a0-11ec-a87a-0242ac110002\"}", 
 "headers": {
    "Content-Type": "application/json", 
    "Access-Control-Allow-Origin": "*"}}
```

#### Verify new record was created

Option 1: Use the DynamoDB Console

Remember: look for the table and 'explore items'.

Option 2: Use the AWS CLI

This method tries to retrieve the new item from DynamoDB:

```bash
aws dynamodb get-item --table-name ws-serverless-patterns-users-Users --key '{"userid": {"S": "<userid-from-response>"}}' 
```

## Connect an API
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch-api.svg)
#### Create the API
#### SAM template.yaml v3 - Connect API
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v3 Connect API

Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"
	    # Next up are connections from the RestAPI to the UsersFunction. API events are connected so they invoke the Lambda function. For each event (ex. get a list of users, get one user by userid, etc.) a _resource path_ and _HTTP method_ are associated with the "RestAPI" resource.
      Events:
        GetUsersEvent:
          Type: Api
          Properties:
            Path: /users
            Method: get
            RestApiId: !Ref RestAPI
        PutUserEvent:
          Type: Api
          Properties:
            Path: /users
            Method: post
            RestApiId: !Ref RestAPI
        UpdateUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: put
            RestApiId: !Ref RestAPI
        GetUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: get
            RestApiId: !Ref RestAPI
        DeleteUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: delete
            RestApiId: !Ref RestAPI
#We named the resource "RestAPI", but remember, this name is just to make it easy to refer to inside the template. This name has no significance outside the template. It could be called, "CustomerAPI", "PrivateAPI", or "CallMeMaybe" so long as the name is used consistently.
  RestAPI:
  #The type is a [SAM resource AWS::Serverless::Api](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html) , which is a collection of Amazon API Gateway resources and methods that can be invoked through HTTP/S endpoints.
    Type: AWS::Serverless::Api
    Properties:
    #The Stage name we chose is "Prod", which indicates this will be used for production. Alternatively, a good practice is to deploy to dev/stage/prod using separate accounts. In that model, the stage name will frequently indicate the version of the API, for example "v1/users" or "v2/users".
      StageName: Prod
      #As mentioned, X-Ray tracing is enabled for this stage with the TracingEnabled flag for active tracking of requests through the system. And the tag section provides additional meta data for reporting and aggregating activity for this stack and the API.
      TracingEnabled: true
      Tags:
        Name: !Sub "${AWS::StackName}-API"
        Stack: !Sub "${AWS::StackName}"      

Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable

  UsersFunction:
    Description: "Lambda function used to perform actions on the users’ data"
    Value: !Ref UsersFunction

  APIEndpoint:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"

```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/api#generated-api-endpoint-url)

#### Generated API endpoint URL

You need a public URL to call the API. The endpoint URL will be generated, so it is added to the template outputs:

```yaml
  APIEndpoint:
    Description: "API Gateway endpoint URL"
    ```yaml
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"
```
[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/api#build-and-deploy)

#### Build and Deploy

Generally, you always need to build before you deploy, so run them both together:

```bash
sam build && sam deploy
```

#### Deploy Checkpoint
Take note of the API Endpoint value from the build. Use it to validate the API works:

```bash
curl <API Endpoint>/users
```
You should see response with one or more user records created by the Lambda function test, similar to the following:

```json
[{"name": "John Doe", "userid": "430a7594-f1a0-11ec-a87a-0242ac110002", "timestamp": "2022-06-21T20:25:16.342221"}]
```
## Secure the API
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch-secure.svg)
[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth#update-template.yaml)

#### Update template.yaml

Paste the following template into `template.yaml` to add Cognito resources:

#### SAM template.yaml v4 - Cognito

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v4 - Cognito

Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

#One new twist in this version of the template is a **Parameters** section. Parameters add a new setting that you will be prompted to enter a value for UserPoolAdminGroupName:
Parameters:
  UserPoolAdminGroupName:
    Description: User pool group name for API administrators 
    Type: String
    Default: apiAdmins

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"
      Events:
        GetUsersEvent:
          Type: Api
          Properties:
            Path: /users
            Method: get
            RestApiId: !Ref RestAPI
        PutUserEvent:
          Type: Api
          Properties:
            Path: /users
            Method: post
            RestApiId: !Ref RestAPI
        UpdateUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: put
            RestApiId: !Ref RestAPI
        GetUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: get
            RestApiId: !Ref RestAPI
        DeleteUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: delete
            RestApiId: !Ref RestAPI

  RestAPI:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      TracingEnabled: true
      Tags:
        Name: !Sub "${AWS::StackName}-API"
        Stack: !Sub "${AWS::StackName}"      

  UserPool:
    Type: AWS::Cognito::UserPool
    Properties: 
      UserPoolName: !Sub ${AWS::StackName}-UserPool
      AdminCreateUserConfig: 
        AllowAdminCreateUserOnly: false
      AutoVerifiedAttributes: 
        - email
      Schema: 
        - Name: name
          AttributeDataType: String
          Mutable: true
          Required: true
        - Name: email
          AttributeDataType: String
          Mutable: true
          Required: true
      UsernameAttributes: 
        - email
      UserPoolTags:
          Key: Name
          Value: !Sub ${AWS::StackName} User Pool

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties: 
      ClientName: 
        !Sub ${AWS::StackName}UserPoolClient
      ExplicitAuthFlows: 
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_USER_SRP_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
      GenerateSecret: false
      PreventUserExistenceErrors: ENABLED
      RefreshTokenValidity: 30
      SupportedIdentityProviders: 
        - COGNITO
      UserPoolId: !Ref UserPool
      AllowedOAuthFlowsUserPoolClient: true
      AllowedOAuthFlows:
        - 'code'
      AllowedOAuthScopes:
        - 'email'
        - 'openid'
      CallbackURLs:
        - 'http://localhost'

  UserPoolDomain:
    Type: AWS::Cognito::UserPoolDomain
    Properties: 
      Domain: !Ref UserPoolClient
      UserPoolId: !Ref UserPool

  ApiAdministratorsUserPoolGroup:
    Type: AWS::Cognito::UserPoolGroup
    Properties:
      Description: User group for API Administrators
      GroupName: !Ref UserPoolAdminGroupName
      Precedence: 0
      UserPoolId: !Ref UserPool

Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable

  UsersFunction:
    Description: "Lambda function used to perform actions on the users data"
    Value: !Ref UsersFunction

  APIEndpoint:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"

  UserPool:
    Description: Cognito User Pool ID
    Value: !Ref UserPool

  UserPoolClient:
    Description: Cognito User Pool Application Client ID
    Value: !Ref UserPoolClient

  UserPoolAdminGroupName:
    Description: User Pool group name for API administrators
    Value: !Ref UserPoolAdminGroupName
  
  CognitoLoginURL:
    Description: Cognito User Pool Application Client Hosted Login UI URL
    Value: !Sub 'https://${UserPoolClient}.auth.${AWS::Region}.amazoncognito.com/login?client_id=${UserPoolClient}&response_type=code&redirect_uri=http://localhost'

  CognitoAuthCommand:
    Description: AWS CLI command for Amazon Cognito User Pool authentication
    Value: !Sub 'aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id ${UserPoolClient} --auth-parameters USERNAME=<user@example.com>,PASSWORD=<password>'
```
**New Resources**

Look at the updated SAM template.yaml, you will see these new resources:

-   UserPool - an AWS::Cognito::UserPool resource, configured with name and email as username
-   UserPoolClient - an entity within a pool with permission to call unauthenticated API operations
-   UserPoolDomain - built in domain (example.com) for authentication
-   ApiAdministratorsUserPoolGroup - user group for API Administrators


As shown previously, running `sam deploy --guided` will give you an opportunity to specify the parameter value or select the default, also selected if you deploy without the guided option.

```bash
sam build && sam deploy --guided
```

**New Outputs**

Stack outputs now include **Cognito** outputs: user pool, client, administrative group, login URL, and authentication CLI commands.

Take note of the **CognitoLoginURL** so that you can test authentication.

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth#deploy-checkpoint-cognito)

## Deploy Checkpoint - Cognito

After deployment finishes, copy the CognitoLoginURL from the outputs and paste into a new browser tab. (Make sure you select the **full URL**.)

You should see a Cognito hosted UI where you can either sign in or sign up for a new account.

![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/sign-in-up-screen.png)
Choose the "Sign up" link and fill in the new user registration form with your email and a password you can remember. You should receive an email with a verification code; use it to confirm your account. Ignore the browser error after you validate your account - the output specified "localhost" as a post-login redirection target, but no application is running on localhost.


##  Authorize w/ JWT
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch-secure-jwt.svg)
[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-jwt#create-an-authorizer-function-for-user-access-control-(authorizer.py))

## Create an Authorizer function for User access control (authorizer.py)

In the src/api/ folder, create a new file called **authorizer.py** and open it in the editor.

Paste the following code into authorizer.py:
#### Source for authorizer function - src/api/authorizer.py
```yaml
import os
import re
import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

# *** Section 1 : base setup and token validation helper function
is_cold_start = True
keys = {}
user_pool_id = os.getenv('USER_POOL_ID', None)
app_client_id = os.getenv('APPLICATION_CLIENT_ID', None)
admin_group_name = os.getenv('ADMIN_GROUP_NAME', None)


def validate_token(token, region):
    global keys, is_cold_start, user_pool_id, app_client_id
    if is_cold_start:
        # KEYS_URL -- REPLACE WHEN CHANGING IDENTITY PROVIDER!!
        keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
        with urllib.request.urlopen(keys_url) as f:
            response = f.read()
        keys = json.loads(response.decode('utf-8'))['keys']
        is_cold_start = False

    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since verification succeeded, you can now safely use the unverified claims
    claims = jwt.get_unverified_claims(token)

    # Additionally you can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        print('Token was not issued for this audience')
        return False
    decoded_jwt = jwt.decode(token, key=keys[key_index], audience=app_client_id)
    return decoded_jwt


def lambda_handler(event, context):
    global admin_group_name
    tmp = event['methodArn'].split(':')
    api_gateway_arn_tmp = tmp[5].split('/')
    region = tmp[3]
    aws_account_id = tmp[4]
    # validate the incoming token
    validated_decoded_token = validate_token(event['authorizationToken'], region)
    if not validated_decoded_token:
        raise Exception('Unauthorized')
    principal_id = validated_decoded_token['sub']
    # initialize the policy
    policy = AuthPolicy(principal_id, aws_account_id)
    policy.restApiId = api_gateway_arn_tmp[0]
    policy.region = region
    policy.stage = api_gateway_arn_tmp[1]

    # *** Section 2 : authorization rules
    # Allow all public resources/methods explicitly

    # Add user specific resources/methods
    policy.allow_method(HttpVerb.GET, f"/users/{principal_id}")
    policy.allow_method(HttpVerb.PUT, f"/users/{principal_id}")
    policy.allow_method(HttpVerb.DELETE, f"/users/{principal_id}")
    policy.allow_method(HttpVerb.GET, f"/users/{principal_id}/*")
    policy.allow_method(HttpVerb.PUT, f"/users/{principal_id}/*")
    policy.allow_method(HttpVerb.DELETE, f"/users/{principal_id}/*")

    # Look for admin group in Cognito groups
    # Assumption: admin group always has higher precedence
    if 'cognito:groups' in validated_decoded_token and validated_decoded_token['cognito:groups'][0] == admin_group_name:
        # add administrative privileges
        policy.allow_method(HttpVerb.GET, "users")
        policy.allow_method(HttpVerb.GET, "users/*")
        policy.allow_method(HttpVerb.DELETE, "users")
        policy.allow_method(HttpVerb.DELETE, "users/*")
        policy.allow_method(HttpVerb.POST, "users")
        policy.allow_method(HttpVerb.PUT, "users/*")

    # Finally, build the policy
    auth_response = policy.build()
    return auth_response



# *** Section 3 : authorization policy helper classes
class HttpVerb:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    HEAD = "HEAD"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    ALL = "*"


class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the appropriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    restApiId = "<<restApiId>>"
    """ Replace the placeholder value with a default API Gateway API id to be used in the policy. 
    Beware of using '*' since it will not simply mean any API Gateway API id, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    region = "<<region>>"
    """ Replace the placeholder value with a default region to be used in the policy. 
    Beware of using '*' since it will not simply mean any region, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    stage = "<<stage>>"
    """ Replace the placeholder value with a default stage to be used in the policy. 
    Beware of using '*' since it will not simply mean any stage, because stars will greedily expand over '/' or other separators. 
    See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html for more details. """

    def __init__(self, principal, aws_account_id):
        self.awsAccountId = aws_account_id
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _add_method(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resource_pattern = re.compile(self.pathRegex)
        if not resource_pattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resource_arn = ("arn:aws:execute-api:" +
                        self.region + ":" +
                        self.awsAccountId + ":" +
                        self.restApiId + "/" +
                        self.stage + "/" +
                        verb + "/" +
                        resource)

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn': resource_arn,
                'conditions': conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn': resource_arn,
                'conditions': conditions
            })

    def _get_empty_statement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _get_statement_for_effect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._get_empty_statement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditional_statement = self._get_empty_statement(effect)
                    conditional_statement['Resource'].append(curMethod['resourceArn'])
                    conditional_statement['Condition'] = curMethod['conditions']
                    statements.append(conditional_statement)

            statements.append(statement)

        return statements

    def allow_all_methods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._add_method("Allow", HttpVerb.ALL, "*", [])

    def deny_all_methods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._add_method("Deny", HttpVerb.ALL, "*", [])

    def allow_method(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._add_method("Allow", verb, resource, [])

    def deny_method(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._add_method("Deny", verb, resource, [])

    def allow_method_with_conditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._add_method("Allow", verb, resource, conditions)

    def deny_method_with_conditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._add_method("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._get_statement_for_effect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._get_statement_for_effect("Deny", self.denyMethods))

        return policy

```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-jwt#what's-happening-in-the-lambda-authorizer)

#### What's happening in the lambda authorizer?

_Wow. That's a lot of code in authorizer.py!?!_

You're right. It is a lot of code, but we can simplify the explanation by breaking the code into three sections:

-   Section 1 (9-63) - mostly boilerplate code to validate the JWT token; except line #21 which specifies the **keys_url** for your IdP
-   Section 2 (66-107) - **code that matters**; your authorization rules are here!
-   Section 3 (111-276) - helper code to make security policy generation easier

####[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-jwt#update-the-sam-template)

## Update the SAM template

Paste the following configuration into `template.yaml` to add an Auth property to the RestAPI, create an AuthorizerFunction resource, and configure a related LogGroup resource.

Expand for SAM template.yaml v5 - JWT Authorizer

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v5 - JWT Authorizer

Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

Parameters:
  UserPoolAdminGroupName:
    Description: User pool group name for API administrators 
    Type: String
    Default: apiAdmins

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"
      Events:
        GetUsersEvent:
          Type: Api
          Properties:
            Path: /users
            Method: get
            RestApiId: !Ref RestAPI
        PutUserEvent:
          Type: Api
          Properties:
            Path: /users
            Method: post
            RestApiId: !Ref RestAPI
        UpdateUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: put
            RestApiId: !Ref RestAPI
        GetUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: get
            RestApiId: !Ref RestAPI
        DeleteUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: delete
            RestApiId: !Ref RestAPI

  RestAPI:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      TracingEnabled: true
      Tags:
        Name: !Sub "${AWS::StackName}-API"
        Stack: !Sub "${AWS::StackName}"      
      Auth:
        DefaultAuthorizer: LambdaTokenAuthorizer
        Authorizers:
          LambdaTokenAuthorizer:
            FunctionArn: !GetAtt AuthorizerFunction.Arn
            Identity:
              Headers:
                - Authorization

  UserPool:
    Type: AWS::Cognito::UserPool
    Properties: 
      UserPoolName: !Sub ${AWS::StackName}-UserPool
      AdminCreateUserConfig: 
        AllowAdminCreateUserOnly: false
      AutoVerifiedAttributes: 
        - email
      Schema: 
        - Name: name
          AttributeDataType: String
          Mutable: true
          Required: true
        - Name: email
          AttributeDataType: String
          Mutable: true
          Required: true
      UsernameAttributes: 
        - email
      UserPoolTags:
          Key: Name
          Value: !Sub ${AWS::StackName} User Pool

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties: 
      ClientName: 
        !Sub ${AWS::StackName}UserPoolClient
      ExplicitAuthFlows: 
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_USER_SRP_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
      GenerateSecret: false
      PreventUserExistenceErrors: ENABLED
      RefreshTokenValidity: 30
      SupportedIdentityProviders: 
        - COGNITO
      UserPoolId: !Ref UserPool
      AllowedOAuthFlowsUserPoolClient: true
      AllowedOAuthFlows:
        - 'code'
      AllowedOAuthScopes:
        - 'email'
        - 'openid'
      CallbackURLs:
        - 'http://localhost'

  UserPoolDomain:
    Type: AWS::Cognito::UserPoolDomain
    Properties: 
      Domain: !Ref UserPoolClient
      UserPoolId: !Ref UserPool

  ApiAdministratorsUserPoolGroup:
    Type: AWS::Cognito::UserPoolGroup
    Properties:
      Description: User group for API Administrators
      GroupName: !Ref UserPoolAdminGroupName
      Precedence: 0
      UserPoolId: !Ref UserPool
#The function type is a SAM resource [AWS::Serverless::Function](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html) which automatically creates not only the Lambda function, but also an Identity and Access Management (IAM) execution role and event source mappings to trigger the function.
  AuthorizerFunction:
    Type: AWS::Serverless::Function
    Properties:
    #Note - the Handler property has a convention of: `<path-to-function>/<function-file-name-without-suffix>.<handler_method_name>`
      Handler: src/api/authorizer.lambda_handler
      Description: Handler for Lambda authorizer
      #make environmental variables available to the function with the Amazon Cognito User Pool and Application Client IDs, and the name of the API administrative users' group in Cognito
      Environment:
        Variables:
          USER_POOL_ID: !Ref UserPool
          APPLICATION_CLIENT_ID: !Ref UserPoolClient
          ADMIN_GROUP_NAME: !Ref UserPoolAdminGroupName
      Tags:
        Stack: !Sub "${AWS::StackName}"

Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable

  UsersFunction:
    Description: "Lambda function used to perform actions on the users data"
    Value: !Ref UsersFunction

  APIEndpoint:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"

  UserPool:
    Description: Cognito User Pool ID
    Value: !Ref UserPool

  UserPoolClient:
    Description: Cognito User Pool Application Client ID
    Value: !Ref UserPoolClient

  UserPoolAdminGroupName:
    Description: User Pool group name for API administrators
    Value: !Ref UserPoolAdminGroupName
  
  CognitoLoginURL:
    Description: Cognito User Pool Application Client Hosted Login UI URL
    Value: !Sub 'https://${UserPoolClient}.auth.${AWS::Region}.amazoncognito.com/login?client_id=${UserPoolClient}&response_type=code&redirect_uri=http://localhost'

  CognitoAuthCommand:
    Description: AWS CLI command for Amazon Cognito User Pool authentication
    Value: !Sub 'aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id ${UserPoolClient} --auth-parameters USERNAME=<username>,PASSWORD=<password>'

```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-jwt#deploy-checkpoint-lambda-authorizer)

#### Deploy Checkpoint - Lambda Authorizer

```bash
sam build && sam deploy
```

## Verify Authorization

In the previous step, you setup a JWT authorizer function for API authentication and authorization.

Next, you will verify your authorization as an administrator to view other users.

Take note of the API Endpoint output and use it to try accessing the API:

```bash
curl <API Endpoint>/users
```

You **should** see a response message that you are `Unauthorized`:

```json
{"message":"Unauthorized"}
```

That shows that **no one** can access your API without valid authentication. Perfect. The next step is to get an authentication token and verify your access through a series of calls to the API.

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-verify#step-1-get-an-identity-token-(idtoken))

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-verify#step-1-get-an-identity-token-(idtoken))

### Step 1 - Get an Identity Token (IdToken)

1.  Copy the `CognitoAuthCommand` command from the stack output
2. Replace **USERNAME** (your email address) and **PASSWORD** with values when you created your account![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/cognito_auth_cmd.jpg)That command should produce an **AccessToken**, **RefreshToken**, and **IdToken**

![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/cognito_auth_response.jpg)
Store the **IdToken** in an environment variable so that it's easy to re-use.

1.  Copy the IdToken value from the output, taking care to select the entire token.:
2.  Run this command to create an environment variable: `export ID_TOKEN="<PASTE TOKEN HERE>"`
3.  Test by running `echo $ID_TOKEN`

Try the API request again to get the list of users, using the identity token as the Authorization header value:

```bash
curl <API_Endpoint>/users -H "Authorization:$ID_TOKEN"
```

This time you should see the message: `“User is not authorized to access this resource"`.

Why?!? That's our fault. We told you to ask for a **list** of users, but you do not have permission to access other peoples data. Regular users can only access their own data. You are currently just a regular user.

To get your own info, you need to know your _principal ID_. The principal ID is created by Cognito and is **not** your userid.

To find get your principal ID, you need to decode and extract it from the JWT token:

1.  Navigate to [https://jwt.io/](https://jwt.io/)

-   Paste in the IdToken value and choose to decode it
-   Take note of the **sub field** in the payload data


Go ahead and try getting data for your principal ID:

```bash
curl <API Endpoint>/users/<sub-value> -H "Authorization:$ID_TOKEN"
```


[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-verify#step-2-add-your-data-via-the-api)

### Step 2 - Add your data via the API

Use the HTTP PUT method to add your user data to the system:

```json
curl --location --request PUT '<YOUR-API-ENDPOINT-URL>/users/<SUB-VALUE>' \
     --data-raw '{"name": "My name is <TYPE YOUR NAME HERE>"}' \
     --header "Authorization: $ID_TOKEN" \  
     --header "Content-Type: application/json" \ 
```

If successful, you should receive confirmation similar to the following: `{"name": "My name is Tim", "timestamp": "2022-12-02T04:20:34.832362", "userid": "5152984a-1a10-47fe-bf38-4fde8339ba64"}`

You should receive the same result running the command to GET /users/ :

```bash
curl <API Endpoint>/users/<sub-value> -H "Authorization:$ID_TOKEN"
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-verify#step-3-add-your-userid-to-the-administrative-group)

### Step 3 - Add your userid to the administrative group

You need to first add your user to the administrators group, so that you can access other users data.

1.  Navigate to the Cognito Management Console
2.  Choose the user pool created for this workshop.
3.  In the Users tab, Choose your user ID and scroll down to the Group memberships section
4.  Choose “Add user to group” button.
5.  Select the Admin group (**apiAdmins**) and choose **Add**.

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/auth-verify#step-4-verify-your-administrative-access)

### Step 4 - Verify your administrative access

Use command present as a stack output **CognitoAuthCommand** from Step #1 to get a new **IdToken**.

This time, when you decode the token, you should see that **apiAdmins** was added to the cognito:groups list.

Try again to retrieve the list of the users, using the new IdToken:

```bash
curl <API Endpoint>/users -H "Authorization:<IdToken value>"
```

## Unit Test
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/test-cycle-491854279.jpg)[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#create-the-test-harness...)

### Create the test harness...

Test-specific dependencies need to be added. These will be used by the testing framework.

Update tests/requirements.txt so that it includes pytest, moto, pytest-freezegun, and requests:

```python
pytest>=7
moto>=3
pytest-freezegun
requests

```

Paste the following test runner code into `tests/unit/test_handler.py` :

Expand for test handler -> tests/unit/test_handler.py

```yml
import json
import os
import boto3
import uuid
import pytest
from moto import mock_dynamodb
from contextlib import contextmanager
from unittest.mock import patch

USERS_MOCK_TABLE_NAME = 'Users'
UUID_MOCK_VALUE_JOHN = 'f8216640-91a2-11eb-8ab9-57aa454facef'
UUID_MOCK_VALUE_JANE = '31a9f940-917b-11eb-9054-67837e2c40b0'
UUID_MOCK_VALUE_NEW_USER = 'new-user-guid'


def mock_uuid():
    return UUID_MOCK_VALUE_NEW_USER


@contextmanager
def my_test_environment():
    with mock_dynamodb():
        set_up_dynamodb()
        put_data_dynamodb()
        yield

def set_up_dynamodb():
    conn = boto3.client(
        'dynamodb'
    )
    conn.create_table(
        TableName=USERS_MOCK_TABLE_NAME,
        KeySchema=[
            {'AttributeName': 'userid', 'KeyType': 'HASH'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'userid', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 1,
            'WriteCapacityUnits': 1
        }
    )
#Before running unit tests, you must set up a test environment. In the `test_handler.py` script, the test_environment() method injects a _mock DynamoDB_ into the environment, then `set_up_dynamodb()` creates a mock Users table, and finally `put_data_dynamodb()` creates the test data.
def put_data_dynamodb():
    conn = boto3.client(
        'dynamodb'
    )
    conn.put_item(
        TableName=USERS_MOCK_TABLE_NAME,
        Item={
            'userid': {'S': UUID_MOCK_VALUE_JOHN},
            'name': {'S': 'John Doe'},
            'timestamp': {'S': '2021-03-30T21:57:49.860Z'}
        }
    )
    conn.put_item(
        TableName=USERS_MOCK_TABLE_NAME,
        Item={
            'userid': {'S': UUID_MOCK_VALUE_JANE},
            'name': {'S': 'Jane Doe'},
            'timestamp': {'S': '2021-03-30T17:13:06.516Z'}
        }
    )

#Here is a typical test which demonstrates the structure to verify the list all users API endpoint:
@patch.dict(os.environ, {'USERS_TABLE': USERS_MOCK_TABLE_NAME, 'AWS_XRAY_CONTEXT_MISSING': 'LOG_ERROR'})
def test_get_list_of_users():
    with my_test_environment():
        from src.api import users
        with open('./events/event-get-all-users.json', 'r') as f:
            apigw_get_all_users_event = json.load(f)
        expected_response = [
            {
                'userid': UUID_MOCK_VALUE_JOHN,
                'name': 'John Doe',
                'timestamp': '2021-03-30T21:57:49.860Z'
            },
            {
                'userid': UUID_MOCK_VALUE_JANE,
                'name': 'Jane Doe',
                'timestamp': '2021-03-30T17:13:06.516Z'
            }
        ]
        ret = users.lambda_handler(apigw_get_all_users_event, '')
        assert ret['statusCode'] == 200
        data = json.loads(ret['body'])
        assert data == expected_response
#The next test, test_get_single_user(), uses the same structure, but a different event payload:
def test_get_single_user():
    with my_test_environment():
        from src.api import users
        with open('./events/event-get-user-by-id.json', 'r') as f:
            apigw_event = json.load(f)
        expected_response = {
            'userid': UUID_MOCK_VALUE_JOHN,
            'name': 'John Doe',
            'timestamp': '2021-03-30T21:57:49.860Z'
        }
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        data = json.loads(ret['body'])
        assert data == expected_response

def test_get_single_user_wrong_id():
    with my_test_environment():
        from src.api import users
        with open('./events/event-get-user-by-id.json', 'r') as f:
            apigw_event = json.load(f)
            apigw_event['pathParameters']['userid'] = '123456789'
            apigw_event['rawPath'] = '/users/123456789'
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        assert json.loads(ret['body']) == {}

@patch('uuid.uuid1', mock_uuid)
@pytest.mark.freeze_time('2001-01-01')
def test_add_user():
    with my_test_environment():
        from src.api import users
        with open('./events/event-post-user.json', 'r') as f:
            apigw_event = json.load(f)
        expected_response = json.loads(apigw_event['body'])
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        data = json.loads(ret['body'])
        assert data['userid'] == UUID_MOCK_VALUE_NEW_USER
        assert data['timestamp'] == '2001-01-01T00:00:00'
        assert data['name'] == expected_response['name']

@pytest.mark.freeze_time('2001-01-01')
def test_add_user_with_id():
    with my_test_environment():
        from src.api import users
        with open('./events/event-post-user.json', 'r') as f:
            apigw_event = json.load(f)
        expected_response = json.loads(apigw_event['body'])
        apigw_event['body'] = apigw_event['body'].replace('}', ', \"userid\":\"123456789\"}')
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        data = json.loads(ret['body'])
        assert data['userid'] == '123456789'
        assert data['timestamp'] == '2001-01-01T00:00:00'
        assert data['name'] == expected_response['name']

def test_delete_user():
    with my_test_environment():
        from src.api import users
        with open('./events/event-delete-user-by-id.json', 'r') as f:
            apigw_event = json.load(f)
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        assert json.loads(ret['body']) == {}
# Add your unit testing code here


```


[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#example-test-request-an-non-existent-user)

### Example test - request an non-existent user

How about testing what happens when a request comes in for a user that does **not** exist in the database?

The API is designed to return a status code 200 and an empty value. The same event data for retrieving one specific user can be re-used, but this test will override the userid value with the request path parameters and raw path value:

```python
def test_get_single_user_wrong_id():
    with test_environment():
        from src.api import users
        with open('./events/event-get-user-by-id.json', 'r') as f:
            apigw_event = json.load(f)
            apigw_event['pathParameters']['userid'] = '123456789'
            apigw_event['rawPath'] = '/users/123456789'
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        assert json.loads(ret['body']) == {}
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#example-test-create-a-user)

### Example test - create a user

So far, the tests have verified that the API works for reading data. The next test checks if Users can be created and updated.

The test loads event data from a JSON file, runs the Lambda handler, and verifies the response userid and timestamps match mock values, and that the returned user name matches the event data:

```python
@patch('uuid.uuid1', mock_uuid)
@pytest.mark.freeze_time('2001-01-01')
def test_add_user():
    with test_environment():
        from src.api import users
        with open('./events/event-post-user.json', 'r') as f:
            apigw_event = json.load(f)
        expected_response = json.loads(apigw_event['body'])
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        data = json.loads(ret['body'])
        assert data['userid'] == UUID_MOCK_VALUE_NEW_USER
        assert data['timestamp'] == '2001-01-01T00:00:00'
        assert data['name'] == expected_response['name']
```

**Did you notice the use of two decorators: @patch and @pytest.mark.freeze_time?**

The Lambda function will generate and assign a new UUID if one is not present in the event data. The `@patch` decorator replaces the standard random uuid generator function (`uuid.uuid1`) with the `mock_uuid()` defined in `test_handler.py`.

The `mock_uuid()` function simply returns a constant UUID_MOCK_VALUE_NEW_USER, which is compared in the later assertion.

Similarly, when the Lambda function sets the timestamp, it will use whatever happens to be the current date and time. That would be difficult to verify, so the test *freezes time at a fixed point with the `@pytest.mark.freeze_time` decorator, and uses that same timestamp when checking the data in the returned event.

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#example-test-update-a-user)

### Example test - update a user

When a user identifier is in the payload, the Lambda function is expected to use it to **update** existing data. When this happens, the last update timestamp should be set to the current date and time. The method `test_add_user_with_id` will verify this scenario by modifying event data so that a user ID is specified in the event payload.

The results will be verified to check that the same user ID in the update is in the response, in this case the userid is "123456789":

```python
@pytest.mark.freeze_time('2001-01-01')
def test_add_user_with_id():
    with test_environment():
        from src.api import users
        with open('./events-post-user.json', 'r') as f:
            apigw_event = json.load(f)
        expected_response = json.loads(apigw_event['body'])
        apigw_event['body'] = apigw_event['body'].replace('}', ', \"userid\":\"123456789\"}')
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        data = json.loads(ret['body'])
        assert data['userid'] == '123456789'
        assert data['timestamp'] == '2001-01-01T00:00:00'
        assert data['name'] == expected_response['name']
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#example-test-delete-a-user)

### Example test - delete a user

The last test case verifies user deletion. Same pattern : load event (JSON file), run Lambda handler, verify expected response status and data:

```python
def test_delete_user():
    with test_environment():
        from src.api import users
        with open('./events/event-delete-user-by-id.json', 'r') as f:
            apigw_event = json.load(f)
        ret = users.lambda_handler(apigw_event, '')
        assert ret['statusCode'] == 200
        assert json.loads(ret['body']) == {}
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#why-do-you-need-test-events)

## Why do you need test events?

We've already talked about using test events, but what are they and why are they needed?

Serverless is event driven, so actions require an input event. Events are represented in JSON.

Take a look at the four (4) test event files in the `events/` folder:

1.  event-get-all-users.json
2.  event-get-user-by-id
3.  event-put-user.json
4.  event-post-user.json
5.  event-delete-user-by-id.json

All of these test events are chunks of JSON in the same structure, or shape, that API Gateway would deliver to the Lambda function. The events contain properties related to the request, such as resource, path, httpMethod, headers, query & path parameters, body, and more.

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#how-to-create-test-events)

## How to create test events

Test events are JSON data files that simulate the data that a service would send or receive. But, how do you create these events?

One option, use the SAM CLI to **generate** events for commonly used services, like API Gateway, S3, SNS, SQS, Cognito.

For example:

```json
Admin:~/environment/serverless-workshop/users $ sam local generate-event apigateway aws-proxy
{
  "body": "eyJ0ZXN0IjoiYm9keSJ9",
  "resource": "/{proxy+}",
  "path": "/path/to/resource",
  "httpMethod": "POST",
  "isBase64Encoded": true,
  "queryStringParameters": {
    "foo": "bar"
  },
  "multiValueQueryStringParameters": {
    "foo": [
      "bar"
    ]
  },
  "pathParameters": {
    "proxy": "/path/to/resource"
  },
  "stageVariables": {
    "baz": "qux"
  },
  "headers": {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, sdch",
    "Accept-Language": "en-US,en;q=0.8",

   // ... more JSON, omitted for brevity ... 
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-unit#run-the-tests...)

#### Run the tests...

Before you run the tests, make sure you are in the application directory in the terminal, then run pip to install all dependencies. You only need to do this once, but make sure the Python virtual is active :
```python
source venv/bin/activate
pip install -r requirements.txt
pip install -r ./tests/requirements.txt

```

Run the unit tests with the following command:

```json
python -m pytest tests/unit -v
```
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/sam-python/unit-test-result.png)
## Integration Test
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/test-cycle-larger_405065784.jpg)
[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-integration#set-up-the-integration-test-harness...)

### Set up the integration test harness...

Prior to running the tests, you need to create a regular and administrative account, and clear previous test data from the data store tables.

Paste the following test environment configuration code into `tests/integration/conftest.py` :

Expand for integration test harness -> tests/integration/conftest.py

```python
import boto3
import os
import pytest
import time

APPLICATION_STACK_NAME = os.getenv('ENV_STACK_NAME', None)
globalConfig = {}

#Get stack outputs with information about resources used by the tests
def get_stack_outputs(stack_name):
    result = {}
    cf_client = boto3.client('cloudformation')
    cf_response = cf_client.describe_stacks(StackName=stack_name)
    outputs = cf_response["Stacks"][0]["Outputs"]
    for output in outputs:
        result[output["OutputKey"]] = output["OutputValue"]
    return result
#Delete and create Amazon Cognito accounts for regular and administrative user, to be used in tests with randomly generated passwords. Get their Identity, Access and refresh JWT tokens
def create_cognito_accounts():
    result = {}
    sm_client = boto3.client('secretsmanager')
    idp_client = boto3.client('cognito-idp')
    # create regular user account
    sm_response = sm_client.get_random_password(ExcludeCharacters='"''`[]{}():;,$/\\<>|=&',
                                                RequireEachIncludedType=True)
    result["regularUserName"] = "regularUser@example.com"
    result["regularUserPassword"] = sm_response["RandomPassword"]
    try:
        idp_client.admin_delete_user(UserPoolId=globalConfig["UserPool"],
                                     Username=result["regularUserName"])
    except idp_client.exceptions.UserNotFoundException:
        print('Regular user haven''t been created previously')
    idp_response = idp_client.sign_up(
        ClientId=globalConfig["UserPoolClient"],
        Username=result["regularUserName"],
        Password=result["regularUserPassword"],
        UserAttributes=[{"Name": "name", "Value": result["regularUserName"]}]
    )
    result["regularUserSub"] = idp_response["UserSub"]
    idp_client.admin_confirm_sign_up(UserPoolId=globalConfig["UserPool"],
                                     Username=result["regularUserName"])
    # get new user authentication info
    idp_response = idp_client.initiate_auth(
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': result["regularUserName"],
            'PASSWORD': result["regularUserPassword"]
        },
        ClientId=globalConfig["UserPoolClient"],
    )
    result["regularUserIdToken"] = idp_response["AuthenticationResult"]["IdToken"]
    result["regularUserAccessToken"] = idp_response["AuthenticationResult"]["AccessToken"]
    result["regularUserRefreshToken"] = idp_response["AuthenticationResult"]["RefreshToken"]
    # create administrative user account
    sm_response = sm_client.get_random_password(ExcludeCharacters='"''`[]{}():;,$/\\<>|=&',
                                                RequireEachIncludedType=True)
    result["adminUserName"] = "adminUser@example.com"
    result["adminUserPassword"] = sm_response["RandomPassword"]
    try:
        idp_client.admin_delete_user(UserPoolId=globalConfig["UserPool"],
                                     Username=result["adminUserName"])
    except idp_client.exceptions.UserNotFoundException:
        print('Regular user haven''t been created previously')
    idp_response = idp_client.sign_up(
        ClientId=globalConfig["UserPoolClient"],
        Username=result["adminUserName"],
        Password=result["adminUserPassword"],
        UserAttributes=[{"Name": "name", "Value": result["adminUserName"]}]
    )
    result["adminUserSub"] = idp_response["UserSub"]
    idp_client.admin_confirm_sign_up(UserPoolId=globalConfig["UserPool"],
                                     Username=result["adminUserName"])
    # add administrative user to the admins group
    idp_client.admin_add_user_to_group(UserPoolId=globalConfig["UserPool"],
                                       Username=result["adminUserName"],
                                       GroupName=globalConfig["UserPoolAdminGroupName"])
    # get new admin user authentication info
    idp_response = idp_client.initiate_auth(
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': result["adminUserName"],
            'PASSWORD': result["adminUserPassword"]
        },
        ClientId=globalConfig["UserPoolClient"],
    )
    result["adminUserIdToken"] = idp_response["AuthenticationResult"]["IdToken"]
    result["adminUserAccessToken"] = idp_response["AuthenticationResult"]["AccessToken"]
    result["adminUserRefreshToken"] = idp_response["AuthenticationResult"]["RefreshToken"]
    return result
#Delete any existing data in the Amazon DynamoDB tables used by the tests
def clear_dynamo_tables():
    # clear all data from the tables that will be used for testing
    dbd_client = boto3.client('dynamodb')
    db_response = dbd_client.scan(
        TableName=globalConfig['UsersTable'],
        AttributesToGet=['userid']
    )
    for item in db_response["Items"]:
        dbd_client.delete_item(
            TableName=globalConfig['UsersTable'],
            Key={'userid': {'S': item['userid']["S"]}}
        )
    return
#Initialize the testing environment
@pytest.fixture(scope='session')
def global_config(request):
    global globalConfig
    # load outputs of the stacks to test
    globalConfig.update(get_stack_outputs(APPLICATION_STACK_NAME))
    globalConfig.update(create_cognito_accounts())
    clear_dynamo_tables()
    return globalConfig

```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-integration#write-integration-test-cases...)

## Write integration test cases...

Paste the following integration testing code into `tests/integration/test_api.py`:

Expand for integration test script -> tests/integration/test_api.py

```yml
import json
import requests

new_user_id = ""
new_user = {"name": "John Doe"}

def test_access_to_the_users_without_authentication(global_config):
    response = requests.get(global_config["APIEndpoint"] + '/users')
    assert response.status_code == 401

def test_get_list_of_users_by_regular_user(global_config):
    response = requests.get(
        global_config["APIEndpoint"] + '/users',
        headers={'Authorization': global_config["regularUserIdToken"]}
    )
    assert response.status_code == 403

def test_deny_post_user_by_regular_user(global_config):
    response = requests.post(
        global_config["APIEndpoint"] + '/users',
        data=json.dumps(new_user),
        headers={'Authorization': global_config["regularUserIdToken"],
                 'Content-Type': 'application/json'}
    )
    assert response.status_code == 403

def test_allow_post_user_by_administrative_user(global_config):
    response = requests.post(
        global_config["APIEndpoint"] + '/users',
        data=json.dumps(new_user),
        headers={'Authorization': global_config["adminUserIdToken"],
                 'Content-Type': 'application/json'}
    )
    assert response.status_code == 200
    data = json.loads(response.text)
    assert data['name'] == new_user['name']
    global new_user_id
    new_user_id = data['userid']

def test_deny_post_invalid_user(global_config):
    new_invalid_user = {"Name": "John Doe"}
    response = requests.post(
        global_config["APIEndpoint"] + '/users',
        data=new_invalid_user,
        headers={'Authorization': global_config["adminUserIdToken"],
                 'Content-Type': 'application/json'}
    )
    assert response.status_code == 400

def test_get_user_by_regular_user(global_config):
    response = requests.get(
        global_config["APIEndpoint"] + f'/users/{new_user_id}',
        headers={'Authorization': global_config["regularUserIdToken"]}
    )
    assert response.status_code == 403

```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/test-integration#run-the-tests...)

### Run the tests...

Run the integration tests with the following commands:

```bash
export ENV_STACK_NAME=ws-serverless-patterns-users
python -m pytest tests/integration -v

```

![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/sam-python/integration-test-result.png)
##  Observe the App
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/cloudwatch-product-diagram.png)

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observability#add-observability-resources)

### Add observability resources

Paste the following template into `template.yaml` to add observability:

Expand for SAM template.yaml v6 - Observability
```yml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v6 - Observability

Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

Parameters:
  UserPoolAdminGroupName:
    Description: User pool group name for API administrators 
    Type: String
    Default: apiAdmins

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"
      Events:
        GetUsersEvent:
          Type: Api
          Properties:
            Path: /users
            Method: get
            RestApiId: !Ref RestAPI
        PutUserEvent:
          Type: Api
          Properties:
            Path: /users
            Method: post
            RestApiId: !Ref RestAPI
        UpdateUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: put
            RestApiId: !Ref RestAPI
        GetUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: get
            RestApiId: !Ref RestAPI
        DeleteUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: delete
            RestApiId: !Ref RestAPI

  RestAPI:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      TracingEnabled: true
      Tags:
        Name: !Sub "${AWS::StackName}-API"
        Stack: !Sub "${AWS::StackName}"
      Auth:
        DefaultAuthorizer: LambdaTokenAuthorizer
        Authorizers:
          LambdaTokenAuthorizer:
            FunctionArn: !GetAtt AuthorizerFunction.Arn
            Identity:
              Headers:
                - Authorization
      AccessLogSetting:
        DestinationArn: !GetAtt AccessLogs.Arn
        Format: '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","routeKey":"$context.routeKey", "status":"$context.status","protocol":"$context.protocol", "integrationStatus": $context.integrationStatus, "integrationLatency": $context.integrationLatency, "responseLength":"$context.responseLength" }'
      MethodSettings:
        - ResourcePath: "/*"
          LoggingLevel: INFO
          HttpMethod: "*"
          DataTraceEnabled: True

  UserPool:
    Type: AWS::Cognito::UserPool
    Properties: 
      UserPoolName: !Sub ${AWS::StackName}-UserPool
      AdminCreateUserConfig: 
        AllowAdminCreateUserOnly: false
      AutoVerifiedAttributes: 
        - email
      Schema: 
        - Name: name
          AttributeDataType: String
          Mutable: true
          Required: true
        - Name: email
          AttributeDataType: String
          Mutable: true
          Required: true
      UsernameAttributes: 
        - email
      UserPoolTags:
          Key: Name
          Value: !Sub ${AWS::StackName} User Pool

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties: 
      ClientName: 
        !Sub ${AWS::StackName}UserPoolClient
      ExplicitAuthFlows: 
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_USER_SRP_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
      GenerateSecret: false
      PreventUserExistenceErrors: ENABLED
      RefreshTokenValidity: 30
      SupportedIdentityProviders: 
        - COGNITO
      UserPoolId: !Ref UserPool
      AllowedOAuthFlowsUserPoolClient: true
      AllowedOAuthFlows:
        - 'code'
      AllowedOAuthScopes:
        - 'email'
        - 'openid'
      CallbackURLs:
        - 'http://localhost' 

  UserPoolDomain:
    Type: AWS::Cognito::UserPoolDomain
    Properties: 
      Domain: !Ref UserPoolClient
      UserPoolId: !Ref UserPool

  ApiAdministratorsUserPoolGroup:
    Type: AWS::Cognito::UserPoolGroup
    Properties:
      Description: User group for API Administrators
      GroupName: !Ref UserPoolAdminGroupName
      Precedence: 0
      UserPoolId: !Ref UserPool                 

  AuthorizerFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/authorizer.lambda_handler
      Description: Handler for Lambda authorizer
      Environment:
        Variables:
          USER_POOL_ID: !Ref UserPool
          APPLICATION_CLIENT_ID: !Ref UserPoolClient
          ADMIN_GROUP_NAME: !Ref UserPoolAdminGroupName
      Tags:
        Stack: !Sub "${AWS::StackName}"

  ApiLoggingRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - apigateway.amazonaws.com
            Action: "sts:AssumeRole"
      Path: /
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs

  ApiGatewayAccountLoggingSettings:
    Type: AWS::ApiGateway::Account
    Properties:
      CloudWatchRoleArn: !GetAtt ApiLoggingRole.Arn

  AccessLogs:
    Type: AWS::Logs::LogGroup
    DependsOn: ApiLoggingRole
    Properties:
      RetentionInDays: 30
      LogGroupName: !Sub "/${AWS::StackName}/APIAccessLogs"

Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable

  UsersFunction:
    Description: "Lambda function used to perform actions on the users data"
    Value: !Ref UsersFunction

  APIEndpoint:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"

  UserPool:
    Description: Cognito User Pool ID
    Value: !Ref UserPool

  UserPoolClient:
    Description: Cognito User Pool Application Client ID
    Value: !Ref UserPoolClient

  UserPoolAdminGroupName:
    Description: User Pool group name for API administrators
    Value: !Ref UserPoolAdminGroupName
    
  CognitoLoginURL:
    Description: Cognito User Pool Application Client Hosted Login UI URL
    Value: !Sub 'https://${UserPoolClient}.auth.${AWS::Region}.amazoncognito.com/login?client_id=${UserPoolClient}&response_type=code&redirect_uri=http://localhost'

  CognitoAuthCommand:
    Description: AWS CLI command for Amazon Cognito User Pool authentication
    Value: !Sub 'aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id ${UserPoolClient} --auth-parameters USERNAME=<username>,PASSWORD=<password>'

```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observability#deploy-checkpoint)

### Deploy checkpoint

Deploy the changes:

```bash
sam build && sam deploy
```

Generate some log entries:

1.  Access the API endpoint or run the integration test
    
    ```bash
    python -m pytest tests/integration -v
    ```
2. Navigate to [CloudWatch Log Groups in AWS Management Console](https://console.aws.amazon.com/cloudwatch/home?#logs:log-groups) You should see /ws-serverless-patterns-users/APIAccessLogs in the log groups:
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/log-group-streams.png)
And you can look for app traces in the X-Ray traces option in the left navigation:
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/xray-traces.png)
## Set Alarms

![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/observe-alarm-sns-email.svg)
[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observe-alarms#add-observability-alarms-resources)

### Add observability - alarms resources

Paste the following configuration with alarm resources into template.yaml:

Expand for SAM template.yaml v7 - Alarms
```yml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v7 - Observability - Alarms

Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

Parameters:
  UserPoolAdminGroupName:
    Description: User pool group name for API administrators 
    Type: String
    Default: apiAdmins

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"
      Events:
        GetUsersEvent:
          Type: Api
          Properties:
            Path: /users
            Method: get
            RestApiId: !Ref RestAPI
        PutUserEvent:
          Type: Api
          Properties:
            Path: /users
            Method: post
            RestApiId: !Ref RestAPI
        UpdateUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: put
            RestApiId: !Ref RestAPI
        GetUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: get
            RestApiId: !Ref RestAPI
        DeleteUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: delete
            RestApiId: !Ref RestAPI

  RestAPI:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      TracingEnabled: true
      Tags:
        Name: !Sub "${AWS::StackName}-API"
        Stack: !Sub "${AWS::StackName}"
      Auth:
        DefaultAuthorizer: LambdaTokenAuthorizer
        Authorizers:
          LambdaTokenAuthorizer:
            FunctionArn: !GetAtt AuthorizerFunction.Arn
            Identity:
              Headers:
                - Authorization
      AccessLogSetting:
        DestinationArn: !GetAtt AccessLogs.Arn
        Format: '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","routeKey":"$context.routeKey", "status":"$context.status","protocol":"$context.protocol", "integrationStatus": $context.integrationStatus, "integrationLatency": $context.integrationLatency, "responseLength":"$context.responseLength" }'
      MethodSettings:
        - ResourcePath: "/*"
          LoggingLevel: INFO
          HttpMethod: "*"
          DataTraceEnabled: True

  UserPool:
    Type: AWS::Cognito::UserPool
    Properties: 
      UserPoolName: !Sub ${AWS::StackName}-UserPool
      AdminCreateUserConfig: 
        AllowAdminCreateUserOnly: false
      AutoVerifiedAttributes: 
        - email
      Schema: 
        - Name: name
          AttributeDataType: String
          Mutable: true
          Required: true
        - Name: email
          AttributeDataType: String
          Mutable: true
          Required: true
      UsernameAttributes: 
        - email
      UserPoolTags:
          Key: Name
          Value: !Sub ${AWS::StackName} User Pool

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties: 
      ClientName: 
        !Sub ${AWS::StackName}UserPoolClient
      ExplicitAuthFlows: 
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_USER_SRP_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
      GenerateSecret: false
      PreventUserExistenceErrors: ENABLED
      RefreshTokenValidity: 30
      SupportedIdentityProviders: 
        - COGNITO
      UserPoolId: !Ref UserPool
      AllowedOAuthFlowsUserPoolClient: true
      AllowedOAuthFlows:
        - 'code'
      AllowedOAuthScopes:
        - 'email'
        - 'openid'
      CallbackURLs:
        - 'http://localhost' 

  UserPoolDomain:
    Type: AWS::Cognito::UserPoolDomain
    Properties: 
      Domain: !Ref UserPoolClient
      UserPoolId: !Ref UserPool

  ApiAdministratorsUserPoolGroup:
    Type: AWS::Cognito::UserPoolGroup
    Properties:
      Description: User group for API Administrators
      GroupName: !Ref UserPoolAdminGroupName
      Precedence: 0
      UserPoolId: !Ref UserPool                 

  AuthorizerFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/authorizer.lambda_handler
      Description: Handler for Lambda authorizer
      Environment:
        Variables:
          USER_POOL_ID: !Ref UserPool
          APPLICATION_CLIENT_ID: !Ref UserPoolClient
          ADMIN_GROUP_NAME: !Ref UserPoolAdminGroupName
      Tags:
        Stack: !Sub "${AWS::StackName}"

  ApiLoggingRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - apigateway.amazonaws.com
            Action: "sts:AssumeRole"
      Path: /
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs

  ApiGatewayAccountLoggingSettings:
    Type: AWS::ApiGateway::Account
    Properties:
      CloudWatchRoleArn: !GetAtt ApiLoggingRole.Arn

  AccessLogs:
    Type: AWS::Logs::LogGroup
    DependsOn: ApiLoggingRole
    Properties:
      RetentionInDays: 30
      LogGroupName: !Sub "/${AWS::StackName}/APIAccessLogs"

  AlarmsTopic:
    Type: AWS::SNS::Topic
    Properties:
      Tags:
        - Key: "Stack" 
          Value: !Sub "${AWS::StackName}"

  RestAPIErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: ApiName
          Value: !Ref RestAPI
      EvaluationPeriods: 1
      MetricName: 5XXError
      Namespace: AWS/ApiGateway
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  AuthorizerFunctionErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref AuthorizerFunction
      EvaluationPeriods: 1
      MetricName: Errors
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0      

  AuthorizerFunctionThrottlingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref AuthorizerFunction
      EvaluationPeriods: 1
      MetricName: Throttles
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  UsersFunctionErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref UsersFunction
      EvaluationPeriods: 1
      MetricName: Errors
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  UsersFunctionThrottlingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref UsersFunction
      EvaluationPeriods: 1
      MetricName: Throttles
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0

Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable

  UsersFunction:
    Description: "Lambda function used to perform actions on the users data"
    Value: !Ref UsersFunction

  APIEndpoint:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"

  UserPool:
    Description: Cognito User Pool ID
    Value: !Ref UserPool

  UserPoolClient:
    Description: Cognito User Pool Application Client ID
    Value: !Ref UserPoolClient

  UserPoolAdminGroupName:
    Description: User Pool group name for API administrators
    Value: !Ref UserPoolAdminGroupName
    
  CognitoLoginURL:
    Description: Cognito User Pool Application Client Hosted Login UI URL
    Value: !Sub 'https://${UserPoolClient}.auth.${AWS::Region}.amazoncognito.com/login?client_id=${UserPoolClient}&response_type=code&redirect_uri=http://localhost'

  CognitoAuthCommand:
    Description: AWS CLI command for Amazon Cognito User Pool authentication
    Value: !Sub 'aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id ${UserPoolClient} --auth-parameters USERNAME=<username>,PASSWORD=<password>'

  AlarmsTopic:
    Description: "SNS Topic to be used for the alarms subscriptions"
    Value: !Ref AlarmsTopic


```



### Deploy Checkpoint

To deploy the changes, run the following commands:

```bash
sam build && sam deploy
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observe-alarms#subscribe-to-sns-topic-via-email)

### Subscribe to SNS topic via email

There are several ways to subscribe to alarms, but the easiest is with an **email** alert.

1.  Go to the Simple Notification Service (SNS) Console
2.  Go to the list of **Topics**
3.  Select the previously created workshop topic.
4.  In the Subscriptions tab, choose to create a subscription. Note: The ARN for your topic should be pre-populated. If not, search for it by name.
5.  Select "Email" for the protocol and add your email address as the Endpoint.

![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/sns-subscribe-to-topic.png)


[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observe-alarms#trigger-some-alarms)

#### Trigger some alarms

**Option 1: add an error to the code!**

In your Users Lambda function, mess something up, and deploy it! For example, change "lambda_handler" to "lambda_handlr" (missing 'e').

Run the unit test suite. Tests should fail. Now, try to access the API. (It should also fail!) Check the logs.

You should see the error in the logs. And, if you subscribed to the SNS queue, you should receive notification from SNS that your Lambda function failed.

**Option 2: Force Lambda function throttling**

Throttling is when your Lambda function is so busy that it cannot handle an additional request. You simulate this by setting the _reserved concurrency_ for the function to zero (0):

```bash
aws lambda put-function-concurrency \
    --function-name  <UsersFunction name from the stack outputs>  \
    --reserved-concurrent-executions 0
```

Again, try accessing the API (which should fail). And, if you subscribed to the SNS queue, you should receive notification from SNS that your Lambda function has been throttled.

Do not forget to set the reserved concurrency back to a reasonable value, like 42, after testing!


## Display a Dashboard
![enter image description here](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/cloudwatch-dash.png)[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observe-dash#add-observability-resources)

### Add observability resources

Paste the following into template.yaml to add an observability dashboard:

Expand for SAM template.yaml v8 - Observability - Dashboard

```yml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  SAM Template for Serverless Patterns v8 - Observability - Dashboard

Globals:
  Function:
    Runtime: python3.9
    MemorySize: 128
    Timeout: 100
    Tracing: Active

Parameters:
  UserPoolAdminGroupName:
    Description: User pool group name for API administrators 
    Type: String
    Default: apiAdmins

Resources:
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: !Sub  ${AWS::StackName}-Users
      AttributeDefinitions:
        - AttributeName: userid
          AttributeType: S
      KeySchema:
        - AttributeName: userid
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST

  UsersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/users.lambda_handler
      Description: Handler for all users related operations
      Environment:
        Variables:
          USERS_TABLE: !Ref UsersTable
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref UsersTable
      Tags:
        Stack: !Sub "${AWS::StackName}"
      Events:
        GetUsersEvent:
          Type: Api
          Properties:
            Path: /users
            Method: get
            RestApiId: !Ref RestAPI
        PutUserEvent:
          Type: Api
          Properties:
            Path: /users
            Method: post
            RestApiId: !Ref RestAPI
        UpdateUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: put
            RestApiId: !Ref RestAPI
        GetUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: get
            RestApiId: !Ref RestAPI
        DeleteUserEvent:
          Type: Api
          Properties:
            Path: /users/{userid}
            Method: delete
            RestApiId: !Ref RestAPI

  RestAPI:
    Type: AWS::Serverless::Api
    Properties:
      StageName: Prod
      TracingEnabled: true
      Tags:
        Name: !Sub "${AWS::StackName}-API"
        Stack: !Sub "${AWS::StackName}"
      Auth:
        DefaultAuthorizer: LambdaTokenAuthorizer
        Authorizers:
          LambdaTokenAuthorizer:
            FunctionArn: !GetAtt AuthorizerFunction.Arn
            Identity:
              Headers:
                - Authorization
      AccessLogSetting:
        DestinationArn: !GetAtt AccessLogs.Arn
        Format: '{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "requestTime":"$context.requestTime", "httpMethod":"$context.httpMethod","routeKey":"$context.routeKey", "status":"$context.status","protocol":"$context.protocol", "integrationStatus": $context.integrationStatus, "integrationLatency": $context.integrationLatency, "responseLength":"$context.responseLength" }'
      MethodSettings:
        - ResourcePath: "/*"
          LoggingLevel: INFO
          HttpMethod: "*"
          DataTraceEnabled: True

  UserPool:
    Type: AWS::Cognito::UserPool
    Properties: 
      UserPoolName: !Sub ${AWS::StackName}-UserPool
      AdminCreateUserConfig: 
        AllowAdminCreateUserOnly: false
      AutoVerifiedAttributes: 
        - email
      Schema: 
        - Name: name
          AttributeDataType: String
          Mutable: true
          Required: true
        - Name: email
          AttributeDataType: String
          Mutable: true
          Required: true
      UsernameAttributes: 
        - email
      UserPoolTags:
          Key: Name
          Value: !Sub ${AWS::StackName} User Pool

  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties: 
      ClientName: 
        !Sub ${AWS::StackName}UserPoolClient
      ExplicitAuthFlows: 
        - ALLOW_USER_PASSWORD_AUTH
        - ALLOW_USER_SRP_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
      GenerateSecret: false
      PreventUserExistenceErrors: ENABLED
      RefreshTokenValidity: 30
      SupportedIdentityProviders: 
        - COGNITO
      UserPoolId: !Ref UserPool
      AllowedOAuthFlowsUserPoolClient: true
      AllowedOAuthFlows:
        - 'code'
      AllowedOAuthScopes:
        - 'email'
        - 'openid'
      CallbackURLs:
        - 'http://localhost' 

  UserPoolDomain:
    Type: AWS::Cognito::UserPoolDomain
    Properties: 
      Domain: !Ref UserPoolClient
      UserPoolId: !Ref UserPool

  ApiAdministratorsUserPoolGroup:
    Type: AWS::Cognito::UserPoolGroup
    Properties:
      Description: User group for API Administrators
      GroupName: !Ref UserPoolAdminGroupName
      Precedence: 0
      UserPoolId: !Ref UserPool                 

  AuthorizerFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/api/authorizer.lambda_handler
      Description: Handler for Lambda authorizer
      Environment:
        Variables:
          USER_POOL_ID: !Ref UserPool
          APPLICATION_CLIENT_ID: !Ref UserPoolClient
          ADMIN_GROUP_NAME: !Ref UserPoolAdminGroupName
      Tags:
        Stack: !Sub "${AWS::StackName}"

  ApiLoggingRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - apigateway.amazonaws.com
            Action: "sts:AssumeRole"
      Path: /
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs

  ApiGatewayAccountLoggingSettings:
    Type: AWS::ApiGateway::Account
    Properties:
      CloudWatchRoleArn: !GetAtt ApiLoggingRole.Arn

  AccessLogs:
    Type: AWS::Logs::LogGroup
    DependsOn: ApiLoggingRole
    Properties:
      RetentionInDays: 30
      LogGroupName: !Sub "/${AWS::StackName}/APIAccessLogs"

  AlarmsTopic:
    Type: AWS::SNS::Topic
    Properties:
      Tags:
        - Key: "Stack" 
          Value: !Sub "${AWS::StackName}"

  RestAPIErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: ApiName
          Value: !Ref RestAPI
      EvaluationPeriods: 1
      MetricName: 5XXError
      Namespace: AWS/ApiGateway
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  AuthorizerFunctionErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref AuthorizerFunction
      EvaluationPeriods: 1
      MetricName: Errors
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0      

  AuthorizerFunctionThrottlingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref AuthorizerFunction
      EvaluationPeriods: 1
      MetricName: Throttles
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  UsersFunctionErrorsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref UsersFunction
      EvaluationPeriods: 1
      MetricName: Errors
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  UsersFunctionThrottlingAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmActions:
        - !Ref AlarmsTopic
      ComparisonOperator: GreaterThanOrEqualToThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref UsersFunction
      EvaluationPeriods: 1
      MetricName: Throttles
      Namespace: AWS/Lambda
      Period: 60
      Statistic: Sum
      Threshold: 1.0

  ApplicationDashboard:
    Type: AWS::CloudWatch::Dashboard
    Properties:
      DashboardName: !Sub "${AWS::StackName}-dashboard"
      DashboardBody:
        Fn::Sub: >
          {
            "widgets": [
                {
                    "height": 6,
                    "width": 6,
                    "y": 6,
                    "x": 0,
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [ "AWS/Lambda", "Invocations", "FunctionName", "${UsersFunction}" ],
                            [ ".", "Errors", ".", "." ],
                            [ ".", "Throttles", ".", "." ],
                            [ ".", "Duration", ".", ".", { "stat": "Average" } ],
                            [ ".", "ConcurrentExecutions", ".", ".", { "stat": "Maximum" } ]
                        ],
                        "view": "timeSeries",
                        "region": "${AWS::Region}",
                        "stacked": false,
                        "title": "Users Lambda",
                        "period": 60,
                        "stat": "Sum"
                    }
                },
                {
                    "height": 6,
                    "width": 6,
                    "y": 6,
                    "x": 6,
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [ "AWS/Lambda", "Invocations", "FunctionName", "${AuthorizerFunction}" ],
                            [ ".", "Errors", ".", "." ],
                            [ ".", "Throttles", ".", "." ],
                            [ ".", "Duration", ".", ".", { "stat": "Average" } ],
                            [ ".", "ConcurrentExecutions", ".", ".", { "stat": "Maximum" } ]
                        ],
                        "view": "timeSeries",
                        "region": "${AWS::Region}",
                        "stacked": false,
                        "title": "Authorizer Lambda",
                        "period": 60,
                        "stat": "Sum"
                    }
                },
                {
                    "height": 6,
                    "width": 12,
                    "y": 0,
                    "x": 0,
                    "type": "metric",
                    "properties": {
                        "metrics": [
                            [ "AWS/ApiGateway", "4XXError", "ApiName", "${AWS::StackName}", { "yAxis": "right" } ],
                            [ ".", "5XXError", ".", ".", { "yAxis": "right" } ],
                            [ ".", "DataProcessed", ".", ".", { "yAxis": "left" } ],
                            [ ".", "Count", ".", ".", { "label": "Count", "yAxis": "right" } ],
                            [ ".", "IntegrationLatency", ".", ".", { "stat": "Average" } ],
                            [ ".", "Latency", ".", ".", { "stat": "Average" } ]
                        ],
                        "view": "timeSeries",
                        "stacked": false,
                        "region": "${AWS::Region}",
                        "period": 60,
                        "stat": "Sum",
                        "title": "API Gateway"
                    }
                }
            ]
          }

Outputs:
  UsersTable:
    Description: DynamoDB Users table
    Value: !Ref UsersTable

  UsersFunction:
    Description: "Lambda function used to perform actions on the users data"
    Value: !Ref UsersFunction

  APIEndpoint:
    Description: "API Gateway endpoint URL"
    Value: !Sub "https://${RestAPI}.execute-api.${AWS::Region}.amazonaws.com/Prod"

  UserPool:
    Description: Cognito User Pool ID
    Value: !Ref UserPool

  UserPoolClient:
    Description: Cognito User Pool Application Client ID
    Value: !Ref UserPoolClient

  UserPoolAdminGroupName:
    Description: User Pool group name for API administrators
    Value: !Ref UserPoolAdminGroupName
    
  CognitoLoginURL:
    Description: Cognito User Pool Application Client Hosted Login UI URL
    Value: !Sub 'https://${UserPoolClient}.auth.${AWS::Region}.amazoncognito.com/login?client_id=${UserPoolClient}&response_type=code&redirect_uri=http://localhost'

  CognitoAuthCommand:
    Description: AWS CLI command for Amazon Cognito User Pool authentication
    Value: !Sub 'aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id ${UserPoolClient} --auth-parameters USERNAME=<username>,PASSWORD=<password>'

  AlarmsTopic:
    Description: "SNS Topic to be used for the alarms subscriptions"
    Value: !Ref AlarmsTopic

  DashboardURL:
    Description: "Dashboard URL"
    Value: !Sub "https://console.aws.amazon.com/cloudwatch/home?region=${AWS::Region}#dashboards:name=${ApplicationDashboard}"

```

The resource type is a CloudWatch dashboard, with a layout and three widgets defined in a JSON array:

1.  Widget #1 - API Gateway metrics
    
    Data fields include: 4XX and 5XX errors, number of requests, latency and integration latency, amount of data processed. We use two separate Y axis used by metrics for better visibility as their ranges of values differ. Note that ${RestAPI} is used in the definition to refer to the resource defined in the template.
    
2.  Widget #2 - Users Lambda function metrics
    
    Data fields include: number of invocations, errors, throttles, average invocation duration and maximum number of concurrent executions. Note that ${UsersFunction} is used in the definition to refer to the resource defined in the same template.
    
3.  Widget #3 - Authorizer Lambda function metrics
    
    Data fields include: number of invocations, errors, throttles, average invocation duration and maximum number of concurrent executions. Note ${AuthorizerFunction} used in the definition to refer to the resource defined in the same template.
For easier access to the dashboard, an Output was added for the dashboard URL:

```yaml
  DashboardURL:
    Description: "Dashboard URL"
    Value: !Sub "https://console.aws.amazon.com/cloudwatch/home?region=${AWS::Region}#dashboards:name=${ApplicationDashboard}"
```

[](https://catalog.workshops.aws/serverless-patterns/en-US/module2/sam-python/observe-dash#deploy-checkpoint)

### Deploy Checkpoint

Deploy the dashboard with the now familiar commands:

```bash
sam build && sam deploy
```
