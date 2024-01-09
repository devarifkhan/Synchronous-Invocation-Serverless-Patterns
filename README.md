# Serverless Patterns Synchronous Invocation
![Application Component: Users Service](https://static.us-east-1.prod.workshops.aws/public/50ba7239-ade8-423c-9236-be127b9939d8/static/module2/module2-arch.svg)
## Create Project with SAM
### 1.  Run `sam init` and follow the prompts to create a new serverless application :
    sam init --name "ws-serverless-patterns" --location "https://ws-assets-prod-iad-r-iad-ed304a55c2ca1aee.s3.us-east-1.amazonaws.com/76bc5278-3f38-46e8-b306-f0bfda551f5a/module2/sam-python/sam-cookiecutter-2023-11-03.zip"
  
  ### 2. At each prompt, accept the default values.
  

    project_name [ws-serverless-patterns]:
    runtime [python3.9]:
    architechtures [default]:
  ### 3. Delete default `samconfig.toml` file
  

    rm samconfig.toml
   
   ### 4. Navigate to `users` directory

    cd ./users

## Create a python Virtual environment

### List default dependencies

    pip freeze
 ### Create a new Virtual environment

    python -m venv venv
  
### Activate the virtual environment

    source venv/bin/activate
### List dependencies again:

```bash
pip freeze
```
    




