import json
threat_action_sc = {}
asset_threat_action = {}
required_asset_threat_action = {}
asset_sc = {}
asset_th_risk = {}
asset_ta_risk = {}

def ta_sc_mapping():
    read_file = open('ResourceFolder/ThreatActionSecurityControlNew.csv','r+')
    for line in read_file:
        line = line.replace('\n','').split(';')
        if line[0] not in threat_action_sc:
            threat_action_sc[line[0]] = []
        threat_action_sc[line[0]].append(line[1])
    print("Threat Action To SC\n%s"%(threat_action_sc))

def analysisCyberARMTA():
    print("Threat Actions")
    file_reader = open('ResourceFolder/ResultFiles/Top_Threat_Action.txt','r+')
    for line in file_reader:
        line = line.replace('\n','').split(',')
        if line[1] in required_asset_threat_action:
            if line[2] in required_asset_threat_action[line[1]]:
                if line[1] not in asset_threat_action:
                    asset_threat_action[line[1]] = []
                asset_threat_action[line[1]].append((line[2],float(line[0])))

    print(asset_threat_action)
    print(len(asset_threat_action))


def analysisCyberARMOutPut():
    print("Analysis CyberARM Output")
    ta_sc_mapping()
    recommendedCDM = readResultFileWithName('ResourceFolder/ResultFiles/OutResult_U_500_0_0.8_0.txt')
    for i in range(len(recommendedCDM)):
        print(recommendedCDM[i])
    for sc in recommendedCDM[0]:
        if sc['asset_name'] not in asset_sc:
            asset_sc[sc['asset_name']] = []
        if sc['sc_version'] not in asset_sc[sc['asset_name']]:
            asset_sc[sc['asset_name']].append(sc['sc_version'])
    print("Asset Security Control %s"%(asset_sc))
    for asset_risk in recommendedCDM[1]:
        if asset_risk['asset_name'] not in asset_threat_action:
            continue
        if asset_risk['asset_name'] not in asset_th_risk:
            asset_th_risk[asset_risk['asset_name']] = []
        asset_th_risk[asset_risk['asset_name']].append(asset_risk['threat_list'])
    for asset_risk in recommendedCDM[3]:
        if asset_risk[0] not in asset_threat_action:
            continue
        if asset_risk[0] not in asset_ta_risk:
            asset_ta_risk[asset_risk[0]] = {}
        for ta_name in asset_risk[1].keys():
            if ta_name not in asset_ta_risk[asset_risk[0]]:
                asset_ta_risk[asset_risk[0]][ta_name] = []
            asset_ta_risk[asset_risk[0]][ta_name].append((asset_risk[1][ta_name][0],asset_risk[1][ta_name][1]))

def readResultFileWithName(readfile):
    recommendedCDM = []
    readFile = open(readfile,'r+')
    for line in readFile:
        line = line.replace("\n", "")
        recommendedCDM.append(json.loads(line))
    print("Length of the Recommended CDM %s" % (len(recommendedCDM)))
    return recommendedCDM

def required_asset_threat_action_extract():
    file_reader = open('ResourceFolder/InputFiles/SelectedThreatActions')
    for line in file_reader:
        line = line.replace('\n', '').split(',')
        if line[0] not in required_asset_threat_action:
            required_asset_threat_action[line[0]] = []
        required_asset_threat_action[line[0]].append(line[1])


def generateOutput():
    final_output = {}
    for asset in asset_threat_action:
        try:
            sc_list = asset_sc[asset]
            final_output[asset] = {}
            for ta in asset_threat_action[asset]:
                if ta[0] not in final_output[asset]:
                    final_output[asset][ta[0]] = []
                for sc in threat_action_sc[ta[0]]:
                    if sc in sc_list:
                        final_output[asset][ta[0]].append(sc)
            # print("Asset %s Sc List %s" % (asset, final_output[asset][ta[0]]))
            final_output[asset][ta[0]] = list(set(final_output[asset][ta[0]]))
            print("Asset %s Threat Action %s Sc List %s"%(asset,ta[0],final_output[asset][ta[0]]))
        except:
            print("No Security Control Selected for %s" % (asset))
    print "Overall Statistics %s" % (final_output)
    print("Asset TA Statistics %s" % (asset_th_risk))
    # for asset in asset_th_risk:
    #     print("Asset Name %s"%(asset))
    #     for ta in asset_th_risk[asset]:
    #         print("\t TA: %s"%(ta))
    for asset in asset_ta_risk:
        print("Asset Name %s"%(asset))
        for ta in asset_ta_risk[asset]:
            print("\t TA: %s : %s"%(ta,asset_ta_risk[asset][ta]))
            residual_risk = sum([asset_ta_risk[asset][ta][i][0] for i in range(len(asset_ta_risk[asset][ta]))])/len(asset_ta_risk[asset][ta])
            prev_risk = sum([asset_ta_risk[asset][ta][i][1] for i in range(len(asset_ta_risk[asset][ta]))]) / len(
                asset_ta_risk[asset][ta])
            print("\t Res: %s (%s); Imp: %s" % (residual_risk,prev_risk,(residual_risk*100)/prev_risk))

if __name__=='__main__':
   required_asset_threat_action_extract()
   analysisCyberARMTA()
   analysisCyberARMOutPut()
   generateOutput()