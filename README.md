Simple Demo how jwts are sent and verified.

Create key from KeyGen or use present.
In Server create token -> /jwt
check that on https://localhost:7062/?t=TOKEN you get guid
Now jwk contains public key which can verify other jwt tokens from External sources, its dummy parsed into External proj.
Jwk-private contains both public key and private key!

External
On the external source you can verify tokens but you cannot create them, check with /jwk (will result in error). Thats because the 
project only has public key from Server.