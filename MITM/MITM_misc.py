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

    filenames = os.listdir("logdir")
    for filename in filenames:
        commandStr = 'head -n 20 {} | grep "logintoken"'.format("MITM/logdir/" + filename)
        content = os.popen(commandStr).read()
        content = content[0:len(content)-1]
        result.append(content)
        print(content)
    return result