# TSAM_PA3
Secure Chat (Secretary of Cat)

SSL passhphrase = "nillinn"

run a SSL client:
openssl s_client -connect IP:PORT

run a SSL server:
openssl s_server -cert src/fd.crt -key src/fd.key -accept PORT
