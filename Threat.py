import ProjectConfigFile
class Threat(object):
    def __init__(self,ids,name,num_asset):
        self.primary_key = ids
        self.threat_name = name
        self.asset_threat_action = []
        self.asset_threat_action_prob = []
        self.asset_threat_action_distribution = []
        self.threat_action_id_to_place_map = {}
        self.number_threat_action = 0
        self.threat_impact_asset = []
        self.global_asset_threat_action = []
        self.global_asset_threat_action_prob = []
        self.global_threat_action_id_to_place_map = []
        self.global_number_threat_action = 0
        self.maximum_risk = []
        self.ignored_threat_action = []
        self.threat_effect = []
        for i in range(num_asset):
            self.asset_threat_action_distribution.append({})
            self.maximum_risk.append(0)
            self.ignored_threat_action.append(1)
            self.threat_effect.append(1.0)

    def considerResidualThreatAction(self):
        for i in range(len(self.global_asset_threat_action)):
            if len(self.asset_threat_action_distribution[i]) == 0:
                self.ignored_threat_action[i] = 0
                continue
            for threat_action_id in self.asset_threat_action_distribution[i].keys():
                if threat_action_id not in self.global_asset_threat_action[i]:
                    self.ignored_threat_action[i] *= (1-self.asset_threat_action_distribution[i][threat_action_id])
            self.ignored_threat_action[i] = 1- self.ignored_threat_action[i]

    def addAssetThreatActionDistribution(self,prob_threat_action_threat_asset,threat_action_name_to_id,asset_index):
        # print "Prob Threat Action Given Threat: %s And Asset: %s \n <><><> List %s" % (self.threat_name,asset_index,prob_threat_action_threat_asset)
        if len(self.asset_threat_action_distribution) <= asset_index:
            print "******** Asset Index is greater than the Threat Action Distribution Dictionary"
            return
        for threat_action in prob_threat_action_threat_asset.keys():
            if threat_action == ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG:
                continue
            self.asset_threat_action_distribution[asset_index][threat_action_name_to_id[threat_action]] = prob_threat_action_threat_asset[threat_action]
            self.threat_effect[asset_index] *= (1-prob_threat_action_threat_asset[threat_action])
        self.threat_effect[asset_index] = self.threat_impact_asset[asset_index]/(1-self.threat_effect[asset_index])

    def determine_maximum_risk(self):
        for i in range(len(self.maximum_risk)):
            # global_risk_threat_action = 1
            # for threat_action_id in self.asset_threat_action_distribution[i].keys():
            #     global_risk_threat_action *= (1-self.asset_threat_action_distribution[i][threat_action_id])
            # self.maximum_risk[i] = (1-global_risk_threat_action)*self.threat_impact_asset[i]
            self.maximum_risk[i] = self.threat_impact_asset[i]

    def clearApplicableThreatActions(self):
        self.threat_action_id_to_place_map.clear()
        del self.asset_threat_action[:]
        del self.asset_threat_action_prob[:]
        self.number_threat_action = 0

    def addThreatActionsAsset(self,threat_action_id):
        self.asset_threat_action.append(threat_action_id)
        self.threat_action_id_to_place_map[threat_action_id] = self.number_threat_action
        self.number_threat_action += 1

    def addThreatImpact(self,risk_threat):
        for i in range(len(risk_threat)):
            for j in range(len(risk_threat[i])):
                if self.threat_name in risk_threat[i][j].keys():
                    self.threat_impact_asset.append(risk_threat[i][j][self.threat_name])
                else:
                    self.threat_impact_asset.append(0)

    def createAssetThreatAction(self,threat_action_id_list_for_specific_asset,asset_name,threat_action_list):
        self.clearApplicableThreatActions()
        for threat_action_id in threat_action_id_list_for_specific_asset:
            if self.threat_name in threat_action_list[threat_action_id].prob_given_threat_asset[asset_name].keys():
                self.asset_threat_action.append(threat_action_id)
                self.asset_threat_action_prob.append(threat_action_list[threat_action_id].prob_given_threat_asset[asset_name][self.threat_name])
                self.threat_action_id_to_place_map[threat_action_id] = self.number_threat_action
                self.number_threat_action += 1

    def globalCreateAssetThreatAction(self,threat_action_id_list_for_asset,asset_enterprise_list,threat_action_list):
        if len(self.global_asset_threat_action) > 0:
            return
        asset_index = 0
        for i in range(len(asset_enterprise_list)):
            for index in range(len(asset_enterprise_list[i])):
                asset_name = asset_enterprise_list[i][index][0]
                self.global_asset_threat_action.append([])
                self.global_asset_threat_action_prob.append([])
                self.global_number_threat_action = 0
                self.global_threat_action_id_to_place_map.append({})
                for threat_action_id in threat_action_id_list_for_asset[asset_index]:
                    # print ":(:((::( %s"%(threat_action_id)
                    if self.threat_name in threat_action_list[threat_action_id].prob_given_threat_asset[asset_name].keys():
                        self.global_asset_threat_action[asset_index].append(threat_action_id)
                        self.global_asset_threat_action_prob[asset_index].append(threat_action_list[threat_action_id].prob_given_threat_asset[asset_name][self.threat_name])
                        self.global_threat_action_id_to_place_map[asset_index][threat_action_id] = self.global_number_threat_action
                        self.global_number_threat_action += 1
                asset_index += 1


    def printProperties(self):
        print "\nID : %s Name : %s" % (self.primary_key,self.threat_name)
        print "Threat Impact %s" % (self.threat_impact_asset)
        print "Threat Action ------->"
        for i in range(len(self.asset_threat_action)):
            print "                          Threat Action ID : %s Prob : %s" % (self.asset_threat_action[i],self.asset_threat_action_prob[i])
        print "                          %s" % (self.asset_threat_action)
        print "                          %s" % (self.asset_threat_action_prob)


    def printGlobalProperties(self):
        print "\nThreat ID: %s, Name: %s" % (self.primary_key,self.threat_name)
        for index in range(len(self.global_asset_threat_action)):
            print "_________ For Asset Index %s" % (index)
            print "                       Risk %s" % (self.threat_impact_asset[index])
            print "                       Maximum Risk %s" % (self.maximum_risk[index])
            print "                       All Threat Action %s" % (self.asset_threat_action_distribution[index])
            print "                       Threat Effect %s" % (self.threat_effect[index])
            print "                       Threat Action %s" % (self.global_asset_threat_action[index])
            print "                       Threat Action Prob %s" % (self.global_asset_threat_action_prob[index])
            print "                       Place of Threat Action %s" % (self.global_threat_action_id_to_place_map[index])
            print "                       Ignored Threat Action %s" % (self.ignored_threat_action[index])