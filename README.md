# Cross Device Authentication Tesing Tool

This tool was created to be able to easily test flaws in different cross device authentication protocols. Services relying on qr-codes and deep-links to authenticate remote or local browser sessions using their own mobile app are becoming increasingly popular, but testing their security can be quite difficult.

This tool relies on a headless browser to test for a simple attack that allows an attacker to start an authentication order against a service, extract or generate a deep link which will trick the victim's application to authenticate the remote session all on the fly as the victim is visiting our web server.

## Attack steps

1. The victim visits the exposed web server hosted on port 8080 (victim can also be taken directly to step 2)
2. The victim clicks on the path hosting the attack
3. The headless browser goes to the target service and starts an authentication order
4. The deep-link is extracted/generated from the authentication order
5. The victim is redirected to the deep-link
    - Via server redirection straight to the deep link
    - To a secondary page that triggers the deep link with js and then navigates to the legitimate service website
6. After the victim authenticates on the service's mobile app our headless browser session will instead be authenticated
