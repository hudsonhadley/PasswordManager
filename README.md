# Password Manager
This project was completed both for practical and learning reasons. It provides
an adequate way to store passwords safely while successfully aiding to learn more about
cryptography, specifically the *Advanced Encryption Standard* (AES), as well as
hashing algorithm, specifically the *MD5* algorithm.

AES, created in 2001 by Joan Daemen and Vincent Rijmen, is still widely used today with no one getting
any nearer to cracking it. Specifically, AES-128 is implemented which, although being
the weakest of the three sibling encryption algorithms, is still a beast. It should
be noted that AES is not implemented in the most efficient way here. This was not my goal.
The goal was to simply learn more about how advanced encryption algorithms work.

MD5 on the other hand is widely regarded as outdated when it comes to hashing
functions. It is close to not being used at all today, and rightly so since many
collision attacks have been found. However, it is only used to expand the keys from 
a password like "123456" into a 128-bit key. These hashes are not available for public 
eyes to see. Additionally, MD5 is part of a more complex function including cryptographic
salt and a certain amount of iterations. All that being said, this system may be 
slightly more secure with a more advanced hashing function such as SHA-1, but it is most
likely secure enough as it is. If one uses a hard enough to guess password, security is
still ensured despite the outdated algorithms use.

MD5 additionally made life a little easier since it creates a 128-bit hash, and AES-128 needs a 128-bit
key. This meant that I didn't need to truncate or concatenate any hashes to make the desired key length.
On top of this, MD5 provided a 'simple enough' algorithm to actually implement while being new to
cryptography and hashing functions. It provided a challenge without being too high of a climb on the first
go around. Being an older function, it also provided resources for implementation, pseudocode, and help from
others who had done this before. I will note as I did with AES: this MD5 implementation is not the most efficient,
for that was not my goal. My goal was to simply learn about how hashing functions work and to dive into one myself.

It also should be noted that running this program inside an IDE terminal will not work because of the password
fields it uses. Running inside the terminal or command prompt or powershell should allow you to use it as intended.

P.S. While I was creating this system, I found that my powershell would insert a new line after a password field. After
some inquiries on 
[stack overflow](https://stackoverflow.com/questions/78551272/why-is-console-readpassword-inserting-a-line) 
I found that others were not having the same problem. I would be interested to know if this is just me and a problem
with my setup or if others are having the same issue.