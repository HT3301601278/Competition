from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from secret import flag,p,q,e


N=p*q
x=81616793159567136422389758585591940662857576283302867011800445277592420866836093507411736040996742950676922327919824777893118631113867500244368612517429678572193116622664051815861481500355863477109385340706136160893878015686817479333596425572252594901263332045777914789662665019123717287533930696370434650226
assert x==p^^q

d = inverse(e, (p-1)*(q-1))

key = RSA.construct((N,e,d,p,q))

cipher = PKCS1_OAEP.new(key)

ciphertext = cipher.encrypt(flag)

f1=open("flag.enc","wb")
f1.write(ciphertext)
f2=open("public.pem","wb")
f2.write(key.publickey().exportKey())

