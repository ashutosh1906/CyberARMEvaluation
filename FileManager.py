import ThreatStatisticsSingleFileCompositionUpdated
import ProjectConfigFile
import numpy
import scipy.stats as stats
from InputFileGenerator import plot_distriution

threat_action_to_security_control_dict = {}
security_control_cost_list = []

def security_control_threat_action_mapping_read():
    number_of_line = 0
    sec_control_file = open(ProjectConfigFile.THREAT_ACTION_SECURITY_CONTROL_FILE,'r+')
    for line in sec_control_file:
        if line == "":
            continue
        line = line.replace('\n','').split(';')
        print line
        if line[0] not in threat_action_to_security_control_dict.keys():
            threat_action_to_security_control_dict[line[0]] = [line[1]]
        else:
            threat_action_to_security_control_dict[line[0]].append(line[1])
        number_of_line += 1
    print threat_action_to_security_control_dict
    sec_control_file.close()
    return number_of_line

def add_effectiveness_security_control_for_threat_action(number_of_mappings):
    write_file = open(ProjectConfigFile.THREAT_ACTION_SECURITY_CONTROL_FILE,'w')
    min_effectiveness,max_effectiveness = 0.49,0.99
    mean_d,s_dev = 0.76,0.12
    distribution = stats.truncnorm.rvs((min_effectiveness-mean_d)/s_dev,(max_effectiveness-mean_d)/s_dev,loc=mean_d,scale=s_dev,size=number_of_mappings)
    # plot_distriution(distribution,mean_d,s_dev)
    index = 0
    for threat_action in threat_action_to_security_control_dict.keys():
        for sec_control in threat_action_to_security_control_dict[threat_action]:
            line = "%s;%s;%s" % (threat_action,sec_control,round(distribution[index],2))
            index += 1
            print line
            write_file.write("%s\n"%(line))
    write_file.close()

def read_security_control():
    del security_control_cost_list[:]
    read_file = open(ProjectConfigFile.SECURITY_CONTROL_FILE,'r+')
    for line in read_file:
        line = line.replace('\n','')
        if line == '':
            continue
        print line
        line = line.split(';')
        security_control_cost_list.append([line[0],line[1],line[2],line[3],line[4]])
    read_file.close()

def write_security_control_cost():
    write_file = open(ProjectConfigFile.SECURITY_CONTROL_FILE,'w')
    cost_distribution = numpy.random.normal(ProjectConfigFile.SECURITY_CONTROL_COST_MEAN,ProjectConfigFile.SECURITY_CONTROL_COST_DEVIATION,len(security_control_cost_list))
    # plot_distriution(cost_distribution,ProjectConfigFile.SECURITY_CONTROL_COST_MEAN,ProjectConfigFile.SECURITY_CONTROL_COST_DEVIATION)
    # for sec_control in security_control_cost_list:
    index = 0
    for sec_con in security_control_cost_list:
        write_file.write("%s;%s;%s;%s;%s;%s\n"%(sec_con[0],sec_con[1],sec_con[2],sec_con[3],sec_con[4],int(cost_distribution[index])))
        index += 1
    write_file.close()

if __name__=="__main__":
    # ################################### Compose Threat Statistics into Single File ##############################
    # ThreatStatisticsSingleFileCompositionUpdated.find_threat_statistics_all()
    #
    # ################################### Effectiveness Distribution ##############################################
    # num_of_threat_action_to_security_control_mapping = security_control_threat_action_mapping_read()
    # print "Number of Threat Action Mappings %s" % (num_of_threat_action_to_security_control_mapping)
    # add_effectiveness_security_control_for_threat_action(num_of_threat_action_to_security_control_mapping)

    ################################# Security Control Cost Distribution ########################################
    read_security_control()
    write_security_control_cost()