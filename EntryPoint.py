import CyberARMPowerPlant,CyberARMEngineUpdated, ProjectConfigFile, Initialization
from CyberARMPowerPlant import threat_threat_action_possible_pair,asset_name_list,threat_threatAction_asset_veris,prob_threat_action_threat,prob_threat,prob_threat_threat_action,security_control_list,security_control_version_to_id
import time

veris_list = []
experience_list = []
def readVerisList():
    """Read the VERIS Asset Input File"""
    veris_list_file = open(ProjectConfigFile.VERIS_LIST_FILE,'r+')
    for line in veris_list_file:
        line = line.replace('\n','').split(',')
        veris_list.append([line[0],[float(line[1]),float(line[2]),float(line[3])]])


if __name__=="__main__":
    # budget = 1497050 ###################### For 150 Assets ###############################
    # budget = 1002900 ########################## For 100 Assets ###############################
    # risk_elimination = .70
    # affordable_risk = 20069579
    ######################################### Read the threat and threat action statistics ###############################################
    Initialization.initializeEnvironment()
    # print "(Init) Threat Threat Action Asset Veris %s" % (threat_threatAction_asset_veris)
    # print "(Init) Asset List %s" % (asset_name_list)
    # print "(Init) Threat Threat Action Possible Pair %s" % (threat_threat_action_possible_pair)

    #################################################### Read The Assets ###########################
    readVerisList()
    # print "VERIS List %s" % (veris_list)
    # veris_list = [['database', [500000, 500000, 500000]], ['desktop', [100000, 100000,
    #                                                                    100000]]]  # ,['laptop',[100000,100000,100000]]]#,['end-user',[100000,100000,100000]]]
    experience_list = []
    experience_list.append([u'laptop_exp', [1222.0, 32345.0, 45678.0],
                            {u'misuse': {u'net misuse': u'32'}, u'hacking': {u'forced browsing': u'329'},
                             u'social': {u'forgery': u'23'}}])
    ############################################# Include the assets ################################
    asset_enterprise_list_input = [[] for i in range(2)]
    asset_enterprise_list_input[ProjectConfigFile.VERIS_LIST] = veris_list
    asset_enterprise_list_input[ProjectConfigFile.EXPERIENCE_LIST] = experience_list

    start_time_whole = time.time()
    total_risk_value = CyberARMEngineUpdated.generate_risk_distribution(asset_enterprise_list_input,CyberARMPowerPlant.send_data)
    if ProjectConfigFile.INCLUDE_ROI == True:
        affordable_risk = total_risk_value - ProjectConfigFile.ROI_VALUE*ProjectConfigFile.BUDGET
        if affordable_risk < 0:
            print("Affordable risk after satosfying the ROI is less than zero and therefore taking the constant variable")
            affordable_risk = ProjectConfigFile.AFFORDABLE_RISK

    else:
        affordable_risk = ProjectConfigFile.AFFORDABLE_RISK
    # print "Received DATA %s" % (CyberARMPowerPlant.send_data)
    max_risk_value_index_variable = len(ProjectConfigFile.RISK_ELIMINATION_LIST)
    success_result = 1
    for max_sec_control_threat_action_index in range(ProjectConfigFile.INITIAL_SEC_THREAT_ACTION,ProjectConfigFile.MAX_SEC_THREAT_ACTION+1):
        print("\n\nMax Security Control per Threat Action Index %s" % (max_sec_control_threat_action_index))
        print("Risk Elimination List Current %s" % (ProjectConfigFile.RISK_ELIMINATION_LIST[0:max_risk_value_index_variable]))
        # success_result = 1
        for risk_elimination_value in ProjectConfigFile.RISK_ELIMINATION_LIST[0:max_risk_value_index_variable]:
            previous_success_result = success_result
            recommendedCDM, success_result = CyberARMPowerPlant.cyberarm_init_main(asset_enterprise_list_input,
                                                                                   affordable_risk,
                                                                                   ProjectConfigFile.BUDGET,
                                                                                   risk_elimination_value,
                                                                                   max_sec_control_threat_action_index)
            if (success_result == 0 and previous_success_result == 0):
                print("Failed in Model Satisfaction %s" % (risk_elimination_value))
                max_risk_value_index_variable = ProjectConfigFile.RISK_ELIMINATION_LIST.index(risk_elimination_value)
                break
            print("Success in Model Satisfaction %s" % (risk_elimination_value))

    ProjectConfigFile.closeFiles()
    print("Total Duration %s" % (time.time() - start_time_whole))