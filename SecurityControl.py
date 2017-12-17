import random
import ProjectConfigFile, ThreatAction
class SecurityControl(object):
    def __init__(self,primary_key,version,name,kill_chain_phase,en_level,sec_func):
        self.primary_key = primary_key
        self.sc_version = version
        self.sc_name = name
        self.kc_phase = ProjectConfigFile.KILL_CHAIN_PHASE_TO_ID[kill_chain_phase]
        self.en_level = ProjectConfigFile.ENFORCEMENT_LEVEL_TO_ID[en_level]
        self.sc_function = ProjectConfigFile.SECURITY_FUNCTION_TO_ID[sec_func]
        self.threat_action = []
        self.threat_action_effectiveness = {}
        self.number_threat_action = 0
        self.asset_threat_action_list = []
        self.global_asset_threat_action_list = []
        self.investment_cost = random.randint(1000,5000)

    def re_init(self):
        del self.threat_action[:]
        self.threat_action_effectiveness.clear()
        self.number_threat_action = 0
        del self.asset_threat_action_list[:]
        del self.global_asset_threat_action_list[:]

    def prepare_global_asset_threat_action_list(self,threat_action_id_list_for_all_assets):
        if len(self.global_asset_threat_action_list) > 0:
            return
        for i in range(len(threat_action_id_list_for_all_assets)):
            self.global_asset_threat_action_list.append([])
            for threat_action in threat_action_id_list_for_all_assets[i]:
                if threat_action in self.threat_action:
                    if threat_action not in self.global_asset_threat_action_list[i]:
                        # print "Threat Action ID %s" % (threat_action)
                        self.global_asset_threat_action_list[i].append(threat_action)

    def clearAllThreatActions(self):
        del self.asset_threat_action_list[:]

    def addAssetThreatAction(self,threat_action_entity_id):
        self.asset_threat_action_list.append(threat_action_entity_id)

    def addThreatAction(self,threat_action_entity_id,effectiveness):
        # print "Threat Actin Entity ID %s" % (threat_action_entity_id)
        if threat_action_entity_id in self.threat_action:
            return
        self.threat_action.append(threat_action_entity_id)
        self.threat_action_effectiveness[threat_action_entity_id] = effectiveness
        self.number_threat_action += 1

    def printProperties(self):
        print "\nID : %s Name : %s" % (self.primary_key,self.sc_name)
        print "Threat Action : ---------> "
        for threat_act in self.asset_threat_action_list:
            print "                                  Threat Action ID : %s ------- Effectiveness : %s" % (threat_act,self.threat_action_effectiveness[threat_act])

    def printGlobalAssetThreatActionProperties(self):
        print "\nSecurity Control ID: %s, Name: %s" % (self.primary_key,self.sc_name)
        print " ::::::::::::: Applicable Against Threat Actions ----> "
        for i in range(len(self.global_asset_threat_action_list)):
            print "Overall Threat Action %s" % (self.threat_action)
            print "                                                       %s" % (self.global_asset_threat_action_list[i])
