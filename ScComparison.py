from Utitilities import readResultFileWithName
import ProjectConfigFile
import random
def readFile():
    withOut_Noise_Index = 0
    withNoise_Index = 3
    rCDM = readResultFileWithName('ResourceFolder/ResultFiles/OutResult_Power2_Up_500_0_0.85_1.txt')
    print("Length of Results %s" % (len(rCDM)))
    cdm_results = []
    for i in range(len(rCDM)/3):
        cdm_results.append(rCDM[i*3])
    print("Length CDM Results %s" % (len(cdm_results)))
    cdm_sec_list = []
    for i in range(len(cdm_results)):
        cdm_sec_list.append({})
        for sc in cdm_results[i]:
            if sc['asset_name'] not in cdm_sec_list[i]:
                cdm_sec_list[i][sc['asset_name']] = []
            else:
                cdm_sec_list[i][sc['asset_name']].append(sc['sc_name'])
    without_noise = cdm_sec_list[withOut_Noise_Index]
    with_noise = cdm_sec_list[withNoise_Index]
    num_deviation = 0
    total_sc = 0
    for asset_name in without_noise.keys():
        total_sc += len(without_noise[asset_name])
        if asset_name not in with_noise:
            num_deviation += without_noise[asset_name]
        else:
            for sc in with_noise[asset_name]:
                if sc not in without_noise[asset_name]:
                    num_deviation += 1
            if len(without_noise[asset_name]) > len(with_noise[asset_name]):
                num_deviation += (len(without_noise[asset_name]) - len(with_noise[asset_name]))

    for asset_name in with_noise.keys():
        if asset_name not in without_noise:
            num_deviation += with_noise[asset_name]

    print("Deviation %s out of %s"%(num_deviation,total_sc))


def introDuceNoiseInFile(noise_percentage):
    read_file = 'ResourceFolder/InputFiles/veris_list_%s_P.txt' %(ProjectConfigFile.VERIS_ASSET_NUMBER)
    write_file = 'ResourceFolder/InputFiles/veris_list_%s_%s_P.txt' % (ProjectConfigFile.VERIS_ASSET_NUMBER,noise_percentage)
    file_read_pointer = open(read_file,'r+')
    file_write_pointer = open(write_file,'w')
    number_iter = (int)(noise_percentage*ProjectConfigFile.VERIS_ASSET_NUMBER)
    noise_id_list = []
    i = 0
    while(True):
        random_num = random.randint(0,ProjectConfigFile.VERIS_ASSET_NUMBER)
        if random_num not in noise_id_list:
            noise_id_list.append(random_num)
            i+=1
        if i>=number_iter:
            break
    print("Noise List length-->(%s) \n%s" % (len(noise_id_list),noise_id_list))
    flag = 1
    i = 0
    threshold = 1
    for line in file_read_pointer:
        line = line.replace('\n','').split(',')
        if i in noise_id_list:
            # print "%s : %s" % (i,line)
            for j in range(1,4):
                line[j] = float(line[j])
                line[j] = line[j] + line[j]*threshold*flag
            # print "%s : %s" % (i, line)
            flag *= (-1)
        line_wrt = line[0]
        for j in range(1,4):
            line_wrt = '%s,%s'%(line_wrt,line[j])
        file_write_pointer.write('%s\n'%(line_wrt))
        i +=1
    file_write_pointer.close()

def introDuceNoiseInFileIncrementally(noise_percentage):
    readFile_noise_index = noise_percentage - 0.05
    if readFile_noise_index == 0:
        read_file = 'ResourceFolder/InputFiles/veris_list_%s.txt' %(ProjectConfigFile.VERIS_ASSET_NUMBER)
    else:
        read_file = 'ResourceFolder/InputFiles/veris_list_%s_%s_N_I.txt' % (ProjectConfigFile.VERIS_ASSET_NUMBER,readFile_noise_index)
    write_file = 'ResourceFolder/InputFiles/veris_list_%s_%s_N_I.txt' % (ProjectConfigFile.VERIS_ASSET_NUMBER,noise_percentage)
    file_read_pointer = open(read_file,'r+')
    file_write_pointer = open(write_file,'w')
    number_iter = (int)(0.05*ProjectConfigFile.VERIS_ASSET_NUMBER)
    noise_id_list = []
    i = 0
    while(True):
        random_num = random.randint(0,ProjectConfigFile.VERIS_ASSET_NUMBER)
        if random_num not in noise_id_list:
            noise_id_list.append(random_num)
            i+=1
        if i>=number_iter:
            break
    print("Noise List length-->(%s) \n%s" % (len(noise_id_list),noise_id_list))
    flag = 1
    i = 0
    threshold = 1
    for line in file_read_pointer:
        line = line.replace('\n','').split(',')
        if i in noise_id_list:
            # print "%s : %s" % (i,line)
            for j in range(1,4):
                line[j] = float(line[j])
                line[j] = line[j] + line[j]*threshold*flag
            # print "%s : %s" % (i, line)
            flag *= (-1)
        line_wrt = line[0]
        for j in range(1,4):
            line_wrt = '%s,%s'%(line_wrt,line[j])
        file_write_pointer.write('%s\n'%(line_wrt))
        i +=1
    file_write_pointer.close()


if __name__=="__main__":
    print("Here the comparison started")
    # readFile()
    noise_value =[0.05,0.1,0.15,0.2,0.25,0.3]
    # noise_value = [0.2,0.25]
    for noise in noise_value:
        introDuceNoiseInFileIncrementally(noise)
    # # # introDuceNoiseInFile(noise_value[2])