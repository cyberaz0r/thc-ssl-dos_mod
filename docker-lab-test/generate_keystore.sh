printf 'changeit\nchangeit\n\n\n\n\n\n\nyes' | keytool -genkey -alias tomcat -keyalg RSA -destkeystore /usr/local/tomcat/conf/tomcat.jks
printf '\n\n\n'
cat /usr/local/tomcat/conf/tomcat.jks | base64 -w0
sleep 5
printf '\n\n\n'
exit
