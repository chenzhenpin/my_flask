import time,os
def datedir(base):
    year=time.strftime('%Y',time.localtime(time.time()))
    #月份
    month=time.strftime('%m',time.localtime(time.time()))
    #日期
    day=time.strftime('%d',time.localtime(time.time()))

    fileYear=base+'/'+year
    fileMonth=fileYear+'/'+month
    fileDay=fileMonth+'/'+day

    if not os.path.exists(fileYear):
        os.mkdir(fileYear)
        os.mkdir(fileMonth)
        os.mkdir(fileDay)
    else:
        if not os.path.exists(fileMonth):
            os.mkdir(fileMonth)
            os.mkdir(fileDay)
        else:
            if not os.path.exists(fileDay):
                os.mkdir(fileDay)
