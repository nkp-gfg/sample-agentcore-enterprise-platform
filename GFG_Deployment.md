# GFG deployment

Do the steps in order. Do not skip a step. Do not run `./scripts/deploy.sh workshop`. That command refuses production mode.

Production mode creates a VPC, a NAT gateway, and interface endpoints. Those bill by the hour. It also keeps logs, the memory store, and the KMS key if someone later deletes the stacks.

This file has no account ids, tenant ids, client ids, organization ids, or email addresses. You collect those yourself and keep them in a notepad outside this repository. `platform.yaml` in a working checkout may already contain one person's values. That file is gitignored. Do not copy it into git.

## Step 1. Clone the repository

```bash
git clone <repository-url>
cd sample-agentcore-enterprise-platform
git checkout n-fe-sandbox-deployment
```

Use the real repository URL. Stay on branch `n-fe-sandbox-deployment`. That branch points the agents at an EU Bedrock profile. Read the exact model id from `presets/production.yaml`. Do not replace it with a `us.` profile if you deploy in an EU Region.

## Step 2. Install the tools

You need these programs before any later command:

- Python 3.13, on the command line as `python3.13`
- Node.js 20, 22, or 24, and npm
- AWS CLI version 2
- A web browser. Entra is done in the portal. Do not install the Azure CLI.
- Bash 4 or newer. The Bash that ships with macOS is too old. On a Mac, run `brew install bash` if a later command complains about Bash.

Docker is not required.

From the repository directory:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Leave this terminal open. Later commands expect the virtualenv to be active. If you open a new terminal, run `source .venv/bin/activate` again from the repository directory.

## Step 3. Sign in

AWS:

```bash
aws login
```

Entra, in the browser:

1. Open [https://entra.microsoft.com](https://entra.microsoft.com).
2. Sign in with your work account.
3. Confirm the tenant name at the top is the tenant that will own the app. If it is the wrong company, switch directory before you continue.

Do not run `export AWS_REGION=...`. A Region variable with that name overrides `platform.yaml`.

## Step 4. Open a notepad

Create a text file outside the repository, for example on your Desktop. Name it `gfg-deploy-notes.txt`. Do not save it inside the git checkout. Do not commit it.

Leave these lines blank. You will fill them in Step 5.

```text
AWS account id:
AWS Region:
AWS Organizations id:
Alarm email:
Redirect URI:
Entra tenant id:
Entra application (client) id:
```

Leave `Redirect URI` blank until the Azure section below. Do not write the client secret in the notepad. Step 8 stores that secret directly in AWS.

## Step 5. How to get each value

Run the commands below. Paste each answer into the matching line in `gfg-deploy-notes.txt`.

### From AWS

Account id. Twelve digits.

```bash
aws sts get-caller-identity --query Account --output text
```

Organizations id. It looks like `o-` followed by letters and numbers.

```bash
aws organizations describe-organization --query Organization.Id --output text
```

If that command says `AWSOrganizationsNotInUseException`, this account is not in an AWS Organization. Production mode cannot deploy without an organization id. Stop and ask the account owner. Do not invent an id.

If that command says `AccessDenied`, your IAM user needs `organizations:DescribeOrganization`.

### You type these yourself

AWS Region. The model id in `presets/production.yaml` starts with `eu.`. Bedrock keeps that profile inside EU Regions. Write an EU Region code, such as `eu-west-1` for Ireland.

Alarm email. Write an inbox a person actually opens. After deploy, AWS sends a confirmation link there. Alarms do nothing until someone clicks the link.

### From Entra, in the browser

Do these clicks in [https://entra.microsoft.com](https://entra.microsoft.com). There is no Azure CLI command in this section.

#### Tenant id

1. Open **Identity** → **Overview**. If you land on the home page, the same **Tenant ID** is on that page.
2. Copy **Tenant ID**. It is a GUID.
3. Paste it onto the `Entra tenant id` line in the notepad.

#### Redirect URI

Cognito does not exist yet, so the Entra portal cannot show you this URL. You build it on your computer, then you paste it into Entra. The shape is fixed:

```text
https://agentcore-production-prod-<account id>.auth.<region>.amazoncognito.com/oauth2/idpresponse
```

`<account id>` is the 12-digit AWS account id in your notepad. `<region>` is the AWS Region in your notepad. Nothing else changes. `agentcore-production-prod` is the project name plus the environment.

In a terminal, replace only the two quoted values with the notepad lines. Leave the quotes.

```bash
ACCOUNT_ID="paste-12-digit-account-id"
REGION="paste-region"
echo "https://agentcore-production-prod-${ACCOUNT_ID}.auth.${REGION}.amazoncognito.com/oauth2/idpresponse"
```

The `echo` line prints one URL. Copy that whole URL onto the `Redirect URI` line in the notepad. It must start with `https://` and end with `/oauth2/idpresponse`. If the printed URL still contains the words `paste-12-digit-account-id` or `paste-region`, you did not replace the quoted values. Run the block again.

#### Register the app and copy the client id

1. Go to **Applications** → **App registrations**.
2. If **AgentCore Accelerator** is already in the list, do not create another. Open it and skip to item 8.
3. Click **New registration**.
4. Name: `AgentCore Accelerator`.
5. Supported account types: **Accounts in this organizational directory only**.
6. Redirect URI: choose platform **Web**, then paste the `Redirect URI` line from the notepad.
7. Click **Register**.
8. On the app **Overview** page, copy **Application (client) ID**. Paste it onto the `Entra application (client) id` line in the notepad. Do not copy **Object ID**.
9. Open **Authentication**. Under **Web**, the redirect URI must match the notepad. If it is missing, click **Add URI**, paste the notepad URL, and click **Save**.
10. On that same **Authentication** page, leave **Access tokens** and **ID tokens** unchecked. This app does not use the implicit flow.

Stop here until every notepad line is filled. Do not create the client secret yet. That is Step 8.

## Step 6. Write `platform.yaml` from the notepad

`platform.yaml` is not in git. A clone does not contain it. Create it in the repository root. Copy each value from `gfg-deploy-notes.txt`. Copy `model_id` from `presets/production.yaml`. Put that same id in `allowed_models`.

```yaml
project: agentcore-production
environment: prod
region: REGION_FROM_NOTEPAD

deployment:
  mode: production
  strategy: centralized
  platform_account: "ACCOUNT_ID_FROM_NOTEPAD"

identity:
  idp: entra_id
  mode: brokered
  tenant_id: TENANT_ID_FROM_NOTEPAD
  client_id: CLIENT_ID_FROM_NOTEPAD
  client_secret_name: agentcore/idp-client-secret

agents:
  pattern: strands-agent
  model_id: MODEL_ID_FROM_PRESET
  allowed_models:
    - MODEL_ID_FROM_PRESET
  memory:
    event_expiry_days: 30

gateway:
  web_search: "off"
  tools: [sample-tool]

security:
  networking: true
  cloudtrail_alerting: true
  resource_policies: true
  egress_filter: true
  require_guardrails: true
  cedar:
    enabled: true
    mode: ENFORCE
  traceability: true
  org_id: ORG_ID_FROM_NOTEPAD

observability:
  transaction_search: true
  alarms: true
  alarm_email: EMAIL_FROM_NOTEPAD
  log_retention_days: 90
```

`client_secret_name` is only a name. It is not the secret. Keep the name `agentcore/idp-client-secret`.

`platform_account` must stay in quotes so YAML does not drop a leading zero.

Do not run `./scripts/deploy.sh design --profile production` after you save this file. `--profile` tries to replace your file with the empty preset.

## Step 7. Run design

Design checks the file and prints the stacks. It does not create AWS resources.

```bash
./scripts/deploy.sh design
```

Stop if you see the word `placeholder` or `INVALID`. A good run shows:

- `Mode: production`
- `Sign-in: entra_id via Cognito (brokered)`
- your account id from the notepad
- your Region from the notepad
- the model id you copied from the preset

It also prints eight stack names that start with `agentcore-production-prod-`. The last line says nothing has been deployed.

The design output includes a line that starts with `register this redirect URI`. That URL must be identical to the `Redirect URI` line in your notepad. If the two differ, the Entra app was registered with the wrong URL. Fix the app in Entra before you continue. Do not change the formula.

## Step 8. Create the secret in Entra, then store it in AWS

Do this before the check in Step 9. The check fails if the secret is missing.

8.1 is the Entra portal. 8.2 through 8.5 are the terminal. Do not copy the password into the notepad, into `platform.yaml`, or into this file. Entra shows the password only once. If you leave the page without copying **Value**, you must make a new client secret.

### 8.1. Create the client secret in the Entra portal

1. Open [https://entra.microsoft.com](https://entra.microsoft.com).
2. Go to **Applications** → **App registrations** → **AgentCore Accelerator**.
3. Open **Certificates & secrets**.
4. Open the **Client secrets** tab.
5. Click **New client secret**.
6. Description: `agentcore`. Pick an expiry your company allows, then click **Add**.
7. In the new row, copy the **Value** column. Do not copy **Secret ID**. **Value** is the password.
8. Keep the password on the clipboard. Do not paste it into the notepad.

### 8.2. Put the password in a local file

This does not call Entra and it does not call AWS. Replace only the quoted Region with the AWS Region from the notepad. Then run the block. The terminal waits with no prompt. Paste the **Value** and press Enter. The paste is hidden.

```bash
REGION="paste-region"
SECRET_FILE="$HOME/agentcore-idp-secret.txt"
umask 077
IFS= read -rs SECRET
printf '%s' "$SECRET" | tr -d '\n\r' > "$SECRET_FILE"
unset SECRET
```

`tr` removes a newline or a space copied from the browser. A leftover newline makes Cognito fail sign-in later with `invalid_client`. Do not open the file. Do not run `cat` on it.

### 8.3. Store that file in AWS Secrets Manager

This talks only to AWS. It reads `$SECRET_FILE` and creates a secret named `agentcore/idp-client-secret` in `$REGION`. Use the same terminal, so `REGION` and `SECRET_FILE` are still set.

```bash
aws secretsmanager create-secret \
  --name agentcore/idp-client-secret \
  --region "$REGION" \
  --secret-string "file://${SECRET_FILE}" \
  --query Name --output text
```

The only output you should see is:

```text
agentcore/idp-client-secret
```

If AWS says the secret already exists, do not create a second one. Update the existing secret with the same file:

```bash
aws secretsmanager put-secret-value \
  --secret-id agentcore/idp-client-secret \
  --region "$REGION" \
  --secret-string "file://${SECRET_FILE}"
```

### 8.4. Delete the local password file

AWS now has the password. Remove the copy on your computer.

```bash
rm -f "$SECRET_FILE"
```

### 8.5. Check the stored password without printing it

This prints a number and the word `True` or `False`. It does not print the password. `True` means the saved value has no space at either end.

```bash
aws secretsmanager get-secret-value \
  --secret-id agentcore/idp-client-secret \
  --region "$REGION" \
  --output json \
  | python3 -c "import json,sys; s=json.load(sys.stdin)['SecretString']; print(len(s), s==s.strip())"
```

You need `True`. If you see `False`, repeat 8.1, then 8.2, then the update command in 8.3, then 8.4 and 8.5.

A secret in a different Region does not count. Another person who deploys into this same account does not need the password. They need permission to read the name `agentcore/idp-client-secret`.

## Step 9. Check that everything is present

This is the last check before deploy. It does not create resources. Every `[FAIL]` must be fixed before Step 10.

```bash
./scripts/deploy.sh doctor
```

If the secret line is a `[FAIL]`, repeat Step 8 in the Region from your notepad. Then run `doctor` again.

`[WARN]` does not block the deploy. `[FAIL]` does.

## Step 10. Deploy

```bash
./scripts/deploy.sh build
```

When the script asks before it creates resources, read the account and Region. Continue only if they match the notepad.

If it asks whether to keep Entra ID, answer yes. If you switch the answer to Cognito, production mode rejects the deploy.

`build` creates eight stacks. Each name starts with `agentcore-production-prod-`:

- `networking`
- `security`
- `auth`
- `identity`
- `memory`
- `gateway`
- `runtime-orchestrator`
- `observability`

## Step 11. Confirm the alarm email

Open the inbox you wrote in the notepad. AWS SNS sent a confirmation message. Click the link. Until you do, alarms have nowhere to go.

## Step 12. Prove the deployment

```bash
./scripts/deploy.sh verify
```

This calls the model, the gateway tool, memory, traces, the guardrail, and the model allow-list. `doctor` does not do that. If `verify` says `AccessDenied` for the model, enable the model id from `presets/production.yaml` in the Bedrock console in your Region, then run `verify` again.
