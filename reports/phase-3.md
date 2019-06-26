### Phase 3 Write-Up

#### Introduction

Hello World!

#### T1: Unauthorized Token Issuance


Asking challenge questions is one way that the system can be more secure, however, it is a weak system because the question/answers are reused. To protect against unauthorized token issuance, the main goal will be to implement a One-Time-Password (OTP) using Two-Factor Authenication (2FA). This mechanism coincides with the separation of privilege notion that a system should not grant permission based on a single condition. 2FA will minimize risk that the user requesting access is an unauthorized user by using a OTP. Using a OTP will be the most secure and user-friendly method to secure the system because the OTP will be generated through mobile devices (?). Using a username/password, the user will identify who they state they are and 2FA verify who they state they are. A sample diagram of how the OTP will work is shown in Figure 1.

**Figure 1: One Time Password Mechanism**
![2FA Mechanism](https://www.researchgate.net/profile/Alex_Chen7/publication/280027625/figure/fig1/AS:391563327885337@1470367381269/A-high-level-overview-of-a-Web-2FA-sequence.png)

In addition to a standard OTP protocol, there will need to be expiration times on two accounts when the system is implemented. Adding an expiration extends this idea to a Time-Based One-Time Password (TOTP). The OTP will only be viable for a set timeframe ie. 30 seconds and afterwards the password will expire. Second, the issued token will only be available or able to be reissued within a set timeframe ie. 2 hours. After the set timeframe, the token will expire and the system will re-prompt for username/password and a OTP. The assumption under this model is that the issuer for the OTP is trusted. 

#### T2: Token Modification/Forgery

There are multiple steps to combat against Token Modification/Forgery. First the underlying principles of least privilege and separation of privilege will need to be used. Using the least privilege principle, a user should only have the persmission level in the system where upon they need to perform a specific task. Using separation of privilege, a user should not be able to make their account into a root account by just having access to the system. The user should be a member of the groupserver as well as know the root password. To ensure that a token is valid, we will use a Certification Authority (CA), a trusted third party 

** **

#### T3: Unauthorized File Server

public key cryptography

#### T4: Information Leakage via Passive Monitoring

To combat information leakage via passive monitoring there will need to be a Transport Layer Security (TLS) implemented. The TLS will prevent information leakage and data integrity between two parties. The TLS is implemented by using symmetric key encryption that is agreed upon after a handshake is completed. 


### References

[Time-Based One-Time Passwords](https://tools.ietf.org/html/rfc6238#section-4)
[Duo Mobile API](https://duo.com/docs/authapi)
