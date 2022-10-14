make clean
make
#sshpass -p "KMz0yCIq" ssh -t root@$1 "sed -i '$ d' /etc/inittab"
#sshpass -p "KMz0yCIq" ssh -t root@$1 "kill -HUP 1"
#sshpass -p "KMz0yCIq" ssh -t root@$1 "killall -9 server"
sshpass -p "KMz0yCIq" ssh -t root@$1 "rm -Rf /home/utente/serverroot/*"
sshpass -p "KMz0yCIq" ssh -t root@$1 "rm -Rf /home/utente/serverfiles/*"
sshpass -p "KMz0yCIq" scp server root@$1:/home/utente
sshpass -p "KMz0yCIq" scp serverfiles/* root@$1:/home/utente/serverfiles/
sshpass -p "KMz0yCIq" scp serverroot/* root@$1:/home/utente/serverroot/
#sshpass -p "KMz0yCIq" ssh -t root@$1 "echo ':3:respawn:/home/utente/server' >> /etc/inittab"
#sshpass -p "KMz0yCIq" ssh -t root@$1 "kill -HUP 1"
