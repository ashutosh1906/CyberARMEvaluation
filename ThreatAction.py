class ThreatAction(object):
    def __init__(self,ids,name):
        self.primary_key = ids
        self.threat_action_name = name
        self.prob_given_threat_asset = {}
        self.applicable_security_controls = []
        self.security_control_index = {}
        self.number_security_controls = 0
        self.asset_applicable_security_controls = []
        self.global_asset_applicable_security = []
        self.asset_security_control_index = {}
        self.global_asset_security_control_index = []
        self.asset_number_security_controls = 0

    def prepare_global_asset_applicable_security_controls(self,selected_security_controls):
        if len(self.global_asset_applicable_security) <> 0:
            return
        for i in range(len(selected_security_controls)):
            self.global_asset_applicable_security.append([])
            self.global_asset_security_control_index.append({})
            number_threat_action = 0
            for sec_control in selected_security_controls[i]:
                if sec_control in self.applicable_security_controls:
                    if sec_control not in self.global_asset_applicable_security[i]:
                        self.global_asset_applicable_security[i].append(sec_control)
                        self.global_asset_security_control_index[i][sec_control] = number_threat_action
                        number_threat_action += 1

    def clearAssetSpecificList(self):
        self.asset_number_security_controls = 0
        self.asset_security_control_index.clear()
        del self.asset_applicable_security_controls[:]

    def addAssetSpecificSecurityControl(self,security_control_entity_id):
        self.asset_security_control_index[security_control_entity_id] = self.asset_number_security_controls
        self.asset_applicable_security_controls.append(security_control_entity_id)
        self.asset_number_security_controls += 1

    def setProbThreatAction(self,prob_threat_action_threat,prob_threat_action_threat_experience,enterprise_asset_list_given):
        for asset in enterprise_asset_list_given:
            if asset not in self.prob_given_threat_asset.keys():
                self.prob_given_threat_asset[asset] = {}
            if asset in prob_threat_action_threat.keys():
                for threat in prob_threat_action_threat[asset].keys():
                    if self.threat_action_name in prob_threat_action_threat[asset][threat].keys():
                        self.prob_given_threat_asset[asset][threat] = prob_threat_action_threat[asset][threat][self.threat_action_name]
            else:
                for threat in prob_threat_action_threat_experience[asset].keys():
                    if self.threat_action_name in prob_threat_action_threat_experience[asset][threat].keys():
                        self.prob_given_threat_asset[asset][threat] = prob_threat_action_threat_experience[asset][threat][self.threat_action_name]

    def addSecurityControl(self,security_control_entity_id):
        if security_control_entity_id in self.applicable_security_controls:
            return
        self.applicable_security_controls.append(security_control_entity_id)
        self.security_control_index[security_control_entity_id] = self.number_security_controls
        self.number_security_controls += 1

    def printProperties(self,asset_name):
        print "\nID : %s Name : %s" % (self.primary_key,self.threat_action_name)
        print "Security Control %s" % (self.asset_applicable_security_controls)
        print "Security Control Index : %s" % (self.asset_security_control_index)
        print "Threat  --->"
        print "     For Asset Name %s " % (asset_name)
        for i in self.prob_given_threat_asset[asset_name].keys():
            print "                                      Threat Name : %s Prob %s" % (i,self.prob_given_threat_asset[asset_name][i])


    def printGlobalAssetThreatActionProperties(self):
        print "\nThreat Action ID: %s, Name: %s" % (self.primary_key,self.threat_action_name)
        print " ::::::::::::: Applicable Security Controls ----> "
        for i in range(len(self.global_asset_applicable_security)):
            print "                                                    %s" % (self.global_asset_applicable_security[i])
            print "                                                    %s" % (self.global_asset_security_control_index[i])