import ProjectConfigFile
import random
import numpy
import matplotlib.pyplot as plt

ASSET_LIST_FILE = 'unique_asset_name.txt'
asset_list_unique = []
VERIS_FILE_INPUT = 'ResourceFolder/InputFiles/veris_list'

def asset_unique_file_generator():
    statfile = open(ProjectConfigFile.WRITE_FILE_NAME,'r+')
    for line in statfile:
        line = line.replace('\n','')
        print line
        if line.startswith(ProjectConfigFile.THREAT_ACTION_TAG_OPEN):
            continue
        if line.startswith(ProjectConfigFile.THREAT_TAG_OPEN):
            continue
        if line.startswith(ProjectConfigFile.ASSET_TAG_WRITE_OPEN):
            print line
            line = line.replace(ProjectConfigFile.ASSET_TAG_WRITE_OPEN, '').replace(ProjectConfigFile.ASSET_TAG_WRITE_CLOSE, '')
            asset_name = line.split(',')
            # print "Asset %s" % (asset_name)
            for asset_unique_name in asset_name:
                try:
                    invalid_asset = float(asset_unique_name)
                except:
                    if asset_unique_name not in asset_list_unique:
                        asset_list_unique.append(asset_unique_name)
    asset_list_unique.remove(ProjectConfigFile.ASSET_UNKNOWN_TAG)
    print "Asset %s" %(asset_list_unique)
    ######################################## Write The Unique Asset List #############################################################
    statfile.close()
    asset_file = open(ASSET_LIST_FILE,'w')
    for asset in asset_list_unique:
        asset_file.write("%s\n"%(asset))
    asset_file.close()


def asset_file_read():
    del asset_list_unique[:]
    asset_file = open(ASSET_LIST_FILE, 'r+')
    for line in asset_file:
        line = line.replace('\n','')
        if len(line) == 0:
            continue
        asset_list_unique.append(line)
    asset_file.close()

def plot_distriution(cia,mean,sd):
    count, bins, ignored = plt.hist(cia, 30, normed=True)
    plt.plot(bins, 1 / (numpy.sqrt(2 * numpy.pi * sd)) * numpy.exp(- (bins - mean) ** 2 / (2 * sd)),
             linewidth=2, color='r')
    plt.show()

if __name__=="__main__":
    # asset_unique_file_generator()
    asset_file_read()
    print asset_list_unique
    number_unique_assets = len(asset_list_unique)
    i = 0
    conf,integrity,availability = [],[],[]
    mean = 130000.0
    standard_deviation = 60000.0
    while i<1000:
        for j in range(10):
            i = i + 10
            file_name = "%s_%s.txt" % (VERIS_FILE_INPUT,i)
            file_name_pointer = open(file_name,'w')
            print "%s" % (i)
            conf = numpy.random.normal(mean,standard_deviation, i)
            integrity = numpy.random.normal(mean,standard_deviation, i)
            availability = numpy.random.normal(mean,standard_deviation, i)
            print conf.size
            for asset_iteration_index in range(i):
                asset_index = random.randint(0,number_unique_assets-1)
                file_name_pointer.write("%s,%s,%s,%s\n"%(asset_list_unique[asset_index],conf[asset_iteration_index],integrity[asset_iteration_index],availability[asset_iteration_index]))
            file_name_pointer.close()

    # iterIn = 0
    # for val in numpy.nditer(conf):
    #     print "%s : %s" %(type(val),val)
    #     iterIn += 1
    # plot_distriution(conf,mean,standard_deviation)
    # plot_distriution(integrity,mean,standard_deviation)
    # plot_distriution(availability,mean,standard_deviation)