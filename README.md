# autopkg-ci info

This project pulls our private recipe, override, and cache repositories. Packages are 
uploaded to Jamf Pro and notifications sent to Microsoft Teams. 

## Configuring Github actions

Configuring this github actions rely on numerous secrets. While many of these values don't 
need to be secret, it was the quickest way to make this project portable without editing 
source code. 

### AutoPKG

#### Secrets
| Name                    | Value                       |
| ----------------------- | --------------------------- |
| AUTOPKG_RECIPE_REPO     | Github Recipe Repo          |
| AUTOPKG_CACHE_REPO      | Github Cache Repo           |
| AUTOPKG_OVERRIDES_REPO  | Github Recipe Override Repo |

### Jamf Pro

Historically I've had issues with Jamf Pro passwords with special characters. I'd 
recommend avoiding them. 

#### Secrets
| Name                    | Value                        |
| ----------------------- | ---------------------------- |
| JSS_URL                 | https://my.jamfpro.com:port  |
| JSS_API_USERNAME        | username                     |
| JSS_API_PASSWORD        | password                     |


### Github

These values should be generated from a service account with limited permissions on your 
repositories. 

#### Secrets
| Name                    | Value                                          |
| ----------------------- | ---------------------------------------------- |
| AUTOPKG_GITHUB_SSH_PRIV | ssh private key used to access repos           |
| AUTOPKG_GITHUB_TOKEN    | Token used to access repos                     |
| AUTOPKG_GITHUB_USER     | Username associated with other github repos    |

### macOS signing information

You'll need to provide a Developer ID Installer certificate & private key in p12 format and the associated password for the p12 file.
You can create the base64 text with this command:

`base64 cert.p12 > cert.txt`

#### Secrets
| Name                    | Value                    |
| ----------------------- | ------------------------ |
| SIGNING_CERT_P112       | p12 in base 64           |
| SIGNING_CERT_PASS       | password to the p12 file |

### Teams

This [article](https://techcommunity.microsoft.com/t5/microsoft-365-pnp-blog/how-to-configure-and-use-incoming-webhooks-in-microsoft-teams/ba-p/2051118) explains how to setup an incoming Webhook. 

Here is the Microsoft documentation used for the Teams integration.
* [Webhooks](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?WT.mc_id=m365-12509-rwilliams)
* [Send Adaptive Cards using an Incoming Webhook](https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using?tabs=cURL#send-adaptive-cards-using-an-incoming-webhook)
* [Create your first adaptive card](https://docs.microsoft.com/en-us/power-automate/create-adaptive-cards)
* [Adaptive Cards](https://adaptivecards.io)

#### Secrets 
| Name                    | Value                                                        |
| ----------------------- | ------------------------------------------------------------ |
| TEAMS_WEBHOOK_URL       | https://****.webhook.office.com                              |


## Running the 'Autopkg' Action

The 'Autopkg' action runs daily. It can also be run manually against the recipe_list.json 
file or provided with a single recipe file name.


## Configuring autopkg locally








