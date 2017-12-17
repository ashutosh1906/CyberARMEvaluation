from CyberARMPowerPlant import prob_threat,prob_threat_action_threat
import ThreatPrioritization,ProjectConfigFile,ThreatPrioritizationExperience

def make_comparator(less_than):
    def compare(x, y):
        if less_than(x, y):
            return -1
        elif less_than(y, x):
            return 1
        else:
            return 0
    return compare


def generate_risk_distribution(asset_enterprise_list,send_data):
    global_risk_threat_action = []
    risk_threat_action_distribution = [[] for i in range(2)]
    risk_threat_distribution = [[] for i in range(2)]
    ThreatPrioritization.calculateRisk(prob_threat,prob_threat_action_threat,asset_enterprise_list[ProjectConfigFile.VERIS_LIST],risk_threat_action_distribution[ProjectConfigFile.VERIS_LIST],risk_threat_distribution[ProjectConfigFile.VERIS_LIST])
    # print "Risk Threat Action %s" % (risk_threat_action_distribution)
    prob_threat_action_threat_experience = {}
    prob_threat_threat_action_experience = {}
    prob_threat_experience = {}
    ThreatPrioritizationExperience.threat_prioritization_main(prob_threat_experience,prob_threat_threat_action_experience,prob_threat_action_threat_experience,risk_threat_action_distribution[ProjectConfigFile.EXPERIENCE_LIST],risk_threat_distribution[ProjectConfigFile.EXPERIENCE_LIST],asset_enterprise_list[ProjectConfigFile.EXPERIENCE_LIST])
    asset_index = 0
    for i in range(len(risk_threat_action_distribution)):
        for j in range(len(risk_threat_action_distribution[i])):
            # print "Risk (%s,%s) : %s" % (i,j,risk_threat_action_distribution[i][j])
            for ta in risk_threat_action_distribution[i][j].keys():
                global_risk_threat_action.append([risk_threat_action_distribution[i][j][ta],asset_index,ta])
            asset_index += 1
    global_risk_threat_action.sort(reverse=True)
    print "Risk Threat Action %s" % (global_risk_threat_action)
    risk_length = len(global_risk_threat_action)
    print "Risk Threat Action Length %s" % (risk_length)
    total_risk_value = sum([global_risk_threat_action[i][0] for i in range(risk_length)])
    print "Total Risk %s" % (total_risk_value)
    sum_percentage = []
    start_index = 0
    distance_percentage = risk_length/10
    rest_element = risk_length - distance_percentage*10
    init_sum = 0
    outer_loop_index = 0
    while start_index < risk_length:
        last_index = start_index + distance_percentage
        if outer_loop_index < rest_element:
            last_index += 1
        if last_index > risk_length:
            last_index = risk_length
        # print "Start Index %s : End Index %s" % (start_index,last_index)
        while start_index < last_index:
            init_sum += global_risk_threat_action[start_index][0]
            start_index += 1
        percentage_sum = round(init_sum/float(total_risk_value)*100,3)
        sum_percentage.append({'risk':percentage_sum,'threat_action':round(start_index/float(risk_length)*100,3)})
        outer_loop_index += 1
    print "This is the percentage %s" % (sum_percentage)
    send_data['percentage'] = sum_percentage
    send_data['global_risk_threat_action'] = global_risk_threat_action