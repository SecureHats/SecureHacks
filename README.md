![logo](./media/securehats-banner.png)
=========
[![GitHub release](https://img.shields.io/github/release/SecureHats/Sentinel-playground.svg?style=flat-square)](https://github.com/SecureHats/SecureHacks/releases)
[![Maintenance](https://img.shields.io/maintenance/yes/2021.svg?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

# SecureHacks

Azure is by default available to every user in the organization. Clients who for instance have Office 365 oftenly haven't set up any conditional access policy to prevent users from logging in to the Azure [portal](https://aad.portal.azure.com) and retrieve every user, role or group. Most of the organizations neither monitor what users are doing in the Azure portal either. So, what if you have a user account in a tenant? What is there to explore and how can we exploit even (default) misconfigurations.

SecureHacks is a project existing out of **PowerShell, Azure CLI** and maybe **Python** scripts for discovery of vulnerabilities in Azure & Azure AD.
Purpose is to create scripts than can be used from any machine, without any flags being triggered by defender or other security tools.

In the documentation an overview of build-in commands can be found for enummeration of accounts, groups, roles, resources, devices etc.

Maybe this project will be extended with files, policies, kusto queries etc. for detecting and remidiating the discoveries.

**_WARNING! The code is for Proof of Concept only and should not be used in production without explict approval of the owner._**

#### Prerequisites

- Access to an Azure (AD) environment
- User Account
