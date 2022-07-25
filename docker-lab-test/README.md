# Docker test lab

This is a docker lab useful for testing Secure Client-Initiated Renegotiation vulnerability.

This docker lab uses an old version of Tomcat (6.0.48) with self-signed SSL certificate, TLS1.2 and Secure Client-Initiated Renegotiation enabled to test the exploit.

To run the lab you just need to run `docker-compose up`.