while true
do
git pull
curl https://urlhaus.abuse.ch/downloads/csv_recent/ -s  | grep -v "#" | grep -v "offline" | cut -d "," -f 3 | sort -u | tr -d \" > malicious_domain.txt && curl https://urlhaus.abuse.ch/dow>
echo "#Log4j IoC from Microsoft Threat Intelligence Center (MSTIC)" > log4j_ioc.txt
curl https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/Log4j_IOC_List.csv -s | grep -v "IP" | sort -u >> log4j_ioc.txt
curl https://feodotracker.abuse.ch/downloads/ipblocklist.csv -s | grep -v "#" | grep -v "dst" | cut -d "," -f 2 | tr -d \" | sort -u > feodoro_tracker_C2.txt
curl https://bazaar.abuse.ch/export/txt/sha256/full/ -s -o sha256.zip && unzip -o sha256.zip && cat full_sha256.txt | grep -v "#" | sort -u > sha256_malware.txt  && rm full_sha256.txt sha2>
sed -r '/^\s*$/d' malicious_domain.txt  > space.txt && mv space.txt malicious_domain.txt
echo "#host file CAN BE CONTAIN FALSE POSITIVE --> adjustment in progress..." > host_file.txt
while IFS= read -r line
do


x=$(echo $line | sed 's/https:\/\///' | sed 's/http:\/\///' | cut -d ":" -f 1 | cut -d "/" -f 1)
if [ $x != "github.com" ]  && [ $x != "raw.githubusercontent.com" ]; then
    echo "0.0.0.0 "$x >>host_file.txt
fi
done < "malicious_domain.txt"
sort -u host_file.txt > a.txt && mv a.txt host_file.txt
git add host_file.txt
git add malicious_domain.txt
git add log4j_ioc.txt
git add feodoro_tracker_C2.txt
git add sha256_malware.txt
git status
git commit -m "feeds"
#git push
git push https://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@github.com/intel-xeon/Threat-intelligence.git
  sleep 600
  clear
done
