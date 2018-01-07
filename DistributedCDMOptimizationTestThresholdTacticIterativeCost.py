from z3 import *
import time
import ProjectConfigFile, Utitilities

def allocated_cost(number_of_unique_asset,global_estimated_risk,risk_asset_specific,alloted_cost_asset_specific,budget):
    for asset_index in range(number_of_unique_asset):
        alloted_cost_asset_specific[asset_index] = budget * risk_asset_specific[asset_index]
    # print "In Allocated Cost: Asset Specific Estimated Risk Proportion %s" % (risk_asset_specific)
    # print "In Allocated Cost: Asset Specific Alloted Cost Proportion %s" % (alloted_cost_asset_specific)

def SMT_Environment(security_control_list,selected_security_controls,threat_action_name_list,threat_action_list,
                    threat_action_id_list_for_all_assets,threat_id_for_all_assets,threat_list,asset_enterprise_list,affordable_risk,budget,cost_effectiveness_sc,risk_ratio_threat_action,
                    global_Total_Cost,global_estimated_risk,global_min_risk,risk_asset_specific,min_sec_control_cost,threat_action_id_to_position_roll,threat_id_to_position_roll,
                    minimum_threat_specific_risk, minimum_affordable_risk):
    print "*********************************************** In Iterative Search ********************************************************************************"
    ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write(
        "*************************** In Iterative Search *****************************\n")
    number_of_unique_asset = len(threat_action_id_list_for_all_assets)

    ############################################### Risk List ############################################################################
    alloted_cost_asset_specific = [0.0 for i in range(number_of_unique_asset)]
    # print "Risk Asset Specific %s" % (risk_asset_specific)

    ######################################################## Prepare a list with the names of the assets ####################################################
    asset_list_for_smt = []
    for i in range(len(asset_enterprise_list)):
        for j in range(len(asset_enterprise_list[i])):
            asset_list_for_smt.append(asset_enterprise_list[i][j])

    print "################################################################# ALl the Problem Specific List #################################################"
    # print "Candidate Selected Threat Action %s" % (threat_action_id_list_for_all_assets)
    # print "Candidate Threat Action Roll %s" % (threat_action_id_to_position_roll)
    # print "Candidate Selected Security Controls %s" % (selected_security_controls)
    # print "Candidate Selected Threat %s" % (threat_id_for_all_assets)
    # print "Candidate Threat Roll %s" % (threat_id_to_position_roll)
    # print "Candidate Security Control Set Cost Effectiveness %s" % (cost_effectiveness_sc)
    print "Global Estimated Risk %s" % (global_estimated_risk)
    print "Global Total Cost %s" % (global_Total_Cost)
    print "Budget %s" % (budget)
    print "Global Minimum Risk %s" % (global_min_risk)

    ###################################################### End of Design of All Heuristics Here ############################################
    ############################################################ Set SMT Environment ####################################################
    set_option(rational_to_decimal=True)
    set_option(precision=3)
    ############################################################ End SMT Environment ####################################################

    ############################################################## Iterate over the SMT #################################################
    budget_variable = budget
    increase_budget = (global_Total_Cost-budget)/ProjectConfigFile.COST_MODEL_ITERATION
    reduced_risk_value_iteration_variable = (affordable_risk - global_min_risk) / ProjectConfigFile.ITERATION_MODEL_SATISFACTION
    CDM_Global_All_Statistice_Iterative = []
    satisfied_risk_variable = global_estimated_risk
    affordable_risk_variable = affordable_risk
    for cost_iteration_index in range(ProjectConfigFile.COST_MODEL_ITERATION):
        cost_iteration_total_time = 0
        CDM_Global_All_Statistice_Iterative_Budget = []
        allocated_cost(number_of_unique_asset, global_estimated_risk, risk_asset_specific, alloted_cost_asset_specific,
                       budget_variable)
        minimum_risk_variable = global_min_risk + 1
        max_security_control_number_variable = int(budget_variable / min_sec_control_cost)
        time_increase_variable = 1
        for model_iteration_index in range(ProjectConfigFile.ITERATION_MODEL_SATISFACTION):
            print "Budget: %s --- Affordable Risk: %s --- Minimum Risk Achievable: %s Satisfied Risk %s" % \
                  (budget_variable, affordable_risk_variable, minimum_risk_variable,satisfied_risk_variable)
            ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write("***** Iteration Number %s\n Budget: %s --- Affordable Risk: %s --- Minimum Risk Achievable: %s Satisfied Risk%s\n" %
                                                     (model_iteration_index,budget_variable, affordable_risk_variable, minimum_risk_variable,satisfied_risk_variable))
            if satisfied_risk_variable <= minimum_risk_variable:
                break

            ############################################################ Declare SMT Solver #####################################################
            cyberARMGoal = Goal()
            cyberARMTactic = Then(Tactic('simplify'), Tactic('solve-eqs'))
            ############################################################ End Declare SMT Solver #################################################

            ############################################################ 1. Declare the variables #################################################
            ############################################################ 1.1 Declare the boolean and cost variables #######################################
            smt_Security_Control_Bool = [[Bool('sec_con_%s_%s' % (i,j)) for j in selected_security_controls[i]] for i in range(len(asset_list_for_smt))]
            # print "SMT Security Control Bool %s" %(smt_Security_Control_Bool)

            smt_Security_Control_Cost = [[Real('sec_con_cost_%s_%s'%(i,j))for j in selected_security_controls[i]] for i in range(len(selected_security_controls))]
            # print "SMT Security Controls Cost %s" % (smt_Security_Control_Cost)
            smt_Total_Security_Control_Cost = [Real('smt_total_sc_cost_%s_%s'%(asset[0],asset_list_for_smt.index(asset))) for asset in asset_list_for_smt]
            # print smt_Total_Security_Control_Cost
            smt_Global_Security_Control_Cost = Real('smt_Global_Security_Control_Cost')
            smt_Security_Control_Flag = [[Int('smt_Security_Control_Flag_%s_%s'%(asset_roll,sec_index)) for sec_index in range(len(selected_security_controls[asset_roll]))] for asset_roll in range(len(selected_security_controls))]
            ############################################################ 1.2 Declare the threat variables #######################################
            smt_Threat = [[Real('Th_%s_%s'%(i,j)) for j in threat_id_for_all_assets[i]] for i in range(len(threat_id_for_all_assets))]
            # print "SMT Threat %s" % (smt_Threat)

            smt_Threat_Threat_Action_Defense_Success = [[[Real('th_ta_%s_%s_%s'%(i,j,k)) for k in threat_list[j].global_asset_threat_action[i]] for j in threat_id_for_all_assets[i]] for i in range(len(threat_id_for_all_assets))]
            # print "SMT THreat Threat Action Defense Success %s" % (smt_Threat_Threat_Action_Defense_Success)
            # for i in threat_list:
            #     print "Threat Impact %s: %s" % (i.primary_key,i.threat_impact_asset)

            ############################################################ 1.3 Declare Threat Action Success Variables#####################################
            smt_Threat_Action_Success = [[Real('t_a_%s_%s'%(i,j)) for j in threat_action_id_list_for_all_assets[i]] for i in range(len(threat_action_id_list_for_all_assets))]
            # print "SMT Threat Action Success %s" % (smt_Threat_Action_Success)

            ############################################################ 1.4 Declare Threat Action Security Control Variables ############################
            smt_Threat_Action_Security_Control = [[
                [Real('t_a_s_c_%s_%s_%s'%(i,j,k)) for k in threat_action_list[j].global_asset_applicable_security[i]]
                for j in threat_action_id_list_for_all_assets[i]]
                for i in range(len(threat_action_id_list_for_all_assets))]

            # for i in range(len(threat_action_id_list_for_all_assets)):
            #     # print "Threat Action %s: %s"%(i,threat_action_id_list_for_all_assets[i])
            #     for threat_action_id in threat_action_id_list_for_all_assets[i]:
            #         print "Threat Action ID %s" % (threat_action_id)
            #         print "Applicable Security Control %s" % (threat_action_list[threat_action_id].global_asset_applicable_security[i])
            #         print "SMT Variable %s" % (smt_Threat_Action_Security_Control[i][threat_action_id_to_position_roll[i][threat_action_id]])

            ############################################################ 1.5 Residual Risk Threshold Threat ############################
            smt_Residual_Risk_Asset = [Real('res_risk_asset_%s_%s'%(i[0],asset_list_for_smt.index(i))) for i in asset_list_for_smt]
            # print "Residual Risk Asset %s" % (smt_Residual_Risk_Asset)
            smt_Global_Residual_Risk = Real('smt_Global_Residual_Risk')

            ############################################################## 1.6 Maximum Number of Security Controls #######################
            smt_Maximum_Number_Security_Control = Real('smt_Maximum_Number_Security_Control')
            ############################################################ End of Declare the boolean variables #######################################

            ##################################################################### Developing Constraints ############################################
            ##################################################################### 2.1 Threat Action Constraint ######################################
            # print "\n**********************************************The main constraints are here ******************************************************************\n"
            for asset_index in range(len(selected_security_controls)):
                # print "**************** Asset Index %s" % (asset_index)
                # print "Selected Sec Controls %s" % (selected_security_controls[asset_index])
                sec_index = 0
                for sec_control in selected_security_controls[asset_index]:
                    for threat_action_id in security_control_list[sec_control].global_asset_threat_action_list[asset_index]:
                        # print "Threat Action ID %s" % (threat_action_id)
                        effectiveness_threat_action = security_control_list[sec_control].threat_action_effectiveness[threat_action_id]
                        # print "Effectiveness Against Threat Action %s" % (effectiveness_threat_action)
                        # print smt_Threat_Action_Security_Control[asset_index][threat_action_id_to_position_roll[asset_index][threat_action_id]]
                        sec_control_position = threat_action_list[threat_action_id].global_asset_security_control_index[asset_index][sec_control]
                        # print "Security Control Position %s" % (sec_control_position)
                        cons = (smt_Threat_Action_Security_Control[asset_index][threat_action_id_to_position_roll[asset_index][threat_action_id]][sec_control_position]==
                                If(smt_Security_Control_Bool[asset_index][sec_index],(1-effectiveness_threat_action),1))
                        cost_cons = (smt_Security_Control_Cost[asset_index][sec_index]==
                                     If(smt_Security_Control_Bool[asset_index][sec_index],
                                      security_control_list[sec_control].investment_cost,0))
                        security_control_flag_cons = (smt_Security_Control_Flag[asset_index][sec_index]==If(smt_Security_Control_Bool[asset_index][sec_index],1,0))
                        cyberARMGoal.add(cons)
                        cyberARMGoal.add(cost_cons)
                        cyberARMGoal.add(security_control_flag_cons)
                    sec_index += 1

            ############################################################# 2.2 Threat Action Success Constraint #####################################
            # print "**************************************************** Threat Action Success ***************************************************"
            for asset_index in range(len(threat_action_id_list_for_all_assets)):
                for threat_action_id in threat_action_id_list_for_all_assets[asset_index]:
                    threat_action_index = threat_action_id_to_position_roll[asset_index][threat_action_id]
                    # print "Threat Action Security Control %s" % (threat_action_list[threat_action_id].global_asset_security_control_index[asset_index])
                    # print "SMT Threat Action Security Control %s" % (smt_Threat_Action_Security_Control[asset_index][threat_action_index])
                    # print "Threat Action Success %s" % (smt_Threat_Action_Success[asset_index][threat_action_index])
                    if len(smt_Threat_Action_Security_Control[asset_index][threat_action_index]) > 0:
                        cyberARMGoal.add(smt_Threat_Action_Success[asset_index][threat_action_index]==
                                     reduce(lambda x,y:x*y,smt_Threat_Action_Security_Control[asset_index][threat_action_index]))
                    else:
                        cyberARMGoal.add(smt_Threat_Action_Success[asset_index][threat_action_index] == 1)

            ############################################################# 2.3 Threat Constraints ##################################################
            # print "\n******************************************* Printing the threat constraint ************************************************\n"
            for asset_index in range(len(threat_id_for_all_assets)):
                # print "\n Asset Index %s" % (asset_index)
                threat_id_index = 0
                for threat_id in threat_id_for_all_assets[asset_index]:
                    # print "SMT THreat %s" % (smt_Threat[asset_index][threat_id_index])
                    # print "Applicable Threat Actions %s" % (threat_list[threat_id].global_asset_threat_action[asset_index])
                    # print "Applicable Threat Actions Probability %s" % (threat_list[threat_id].global_asset_threat_action_prob[asset_index])
                    # print "SMT Threat THreat Actions %s" % (smt_Threat_Threat_Action_Defense_Success[asset_index][threat_id_index])
                    # print "Threat Impact %s" % (threat_list[threat_id].threat_impact_asset[asset_index])
                    threat_action_index = 0
                    for threat_action in threat_list[threat_id].global_asset_threat_action[asset_index]:
                        # print "Applicable Threat Action %s" % (smt_Threat_Action_Success[asset_index][threat_action_id_to_position_roll[asset_index][threat_action]])
                        # print "Prob %s" % (threat_list[threat_id].global_asset_threat_action_prob[asset_index][threat_action_index])
                        # print "Applicable SMT Threat Threat Actions %s" % (smt_Threat_Threat_Action_Defense_Success[asset_index][threat_id_index][threat_action_index])
                        cyberARMGoal.add(smt_Threat_Threat_Action_Defense_Success[asset_index][threat_id_index][threat_action_index]==
                                     (1-smt_Threat_Action_Success[asset_index][threat_action_id_to_position_roll[asset_index][threat_action]]
                                      *threat_list[threat_id].global_asset_threat_action_prob[asset_index][threat_action_index]))
                        threat_action_index += 1
                    if len(smt_Threat_Threat_Action_Defense_Success[asset_index][threat_id_index]) > 0:
                        cyberARMGoal.add(smt_Threat[asset_index][threat_id_index]==
                                     (1-reduce(lambda x,y:x*y,smt_Threat_Threat_Action_Defense_Success[asset_index][threat_id_index])
                                      *(1-threat_list[threat_id].ignored_threat_action[asset_index]))
                                     *threat_list[threat_id].threat_effect[asset_index])
                    else:
                        cyberARMGoal.add(smt_Threat[asset_index][threat_id_index]==threat_list[threat_id].ignored_threat_action[asset_index]*threat_list[threat_id].threat_effect[asset_index])
                    threat_id_index += 1

            ############################################################# 2.4 Residual Risk Constraints ##################################################

            cyberARMGoal.add([smt_Residual_Risk_Asset[i]==sum(smt_Threat[i]) for i in range(len(smt_Residual_Risk_Asset))])
            cyberARMGoal.add([smt_Residual_Risk_Asset[i] >= (minimum_affordable_risk[i]-1) for i in range(len(minimum_affordable_risk))])
            cyberARMGoal.add(smt_Global_Residual_Risk == sum(smt_Residual_Risk_Asset))
            # cyberARMGoal.add(smt_Global_Residual_Risk > sum(minimum_affordable_risk))
            cyberARMGoal.add(smt_Global_Residual_Risk > (minimum_risk_variable-2))
            ########################################################### 2.5 Total Security Control Cost ##################################################
            cyberARMGoal.add([smt_Total_Security_Control_Cost[asset_index]==sum(smt_Security_Control_Cost[asset_index]) for asset_index in range(len(asset_list_for_smt))])
            cyberARMGoal.add(smt_Global_Security_Control_Cost==sum(smt_Total_Security_Control_Cost))
            cyberARMGoal.add(smt_Global_Security_Control_Cost <= budget_variable)
            # for asset_index in range(number_of_unique_asset):
            #     cyberARMGoal.add(smt_Total_Security_Control_Cost[asset_index] < (alloted_cost_asset_specific[asset_index]+0.1))
            ########################################################### 2.6 Maximum Number of Security Controls ############################################
            cyberARMGoal.add(smt_Maximum_Number_Security_Control == sum([sum([smt_Security_Control_Flag[asset_index][sec_index] for sec_index in range(len(selected_security_controls[asset_index]))]) for asset_index in range(len(selected_security_controls))]))
            cyberARMGoal.add(smt_Maximum_Number_Security_Control <= max_security_control_number_variable)

            ########################################################### Discover The Most Cost Effective Pattern #####################################

            ############################################################ 2.6 Add The Total Residual Risk #############################################
            print "***** Iteration Number %s :::: Affordable Risk %s *********" % (model_iteration_index,affordable_risk_variable)
            # cyberARM.push()
            cyberARMGoal.add(smt_Global_Residual_Risk <= affordable_risk_variable)
            ############################################################ End Constrainst Development #################################################
            ############################################################ 3. Check the model ##########################################################
            simplifiedResult = cyberARMTactic(cyberARMGoal)
            # print "Length %s" % (len(simplifiedResult))
            cyberARM = Solver()
            # cyberARM = Optimize()
            for simRes in simplifiedResult:
                # print "Constraints %s" % (simRes)
                cyberARM.add(simRes)
            # cyberARM.minimize(smt_Global_Residual_Risk)
            print time.ctime()
            print "Time Limitation %s" % (int(time_increase_variable * ProjectConfigFile.TIMEOUT_DURATION))
            ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write(
                "Time Limitation %s\n" % (int(time_increase_variable * ProjectConfigFile.TIMEOUT_DURATION)))
            start_time = time.time()
            cyberARM.set("timeout",int(time_increase_variable*ProjectConfigFile.TIMEOUT_DURATION))
            satisfiability = cyberARM.check()
            time_required_specific = time.time() - start_time
            print "Satisfiability %s" % (satisfiability)
            ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write(
                "Time Required for Solution %s\n" % (time_required_specific))
            print "Time Required for Solution %s" % (time_required_specific)
            cost_iteration_total_time += time_required_specific
            ############################################################ 4. Get The Model ############################################################

            recommended_CDM = None
            # print "Try %s" % (recommended_CDM.check())
            if satisfiability == z3.sat:
                recommended_CDM = cyberARM.model()
                # print "Model %s" % (recommended_CDM)

            else:
                print "There is no satisfiable model"
                ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write("There is no satisfiable model\n\n")
                recommended_CDM = []
                recommended_CDM.insert(ProjectConfigFile.CYBERARM_CDM_MATRIX, [])
                recommended_CDM.insert(ProjectConfigFile.CYBERARM_RISK, [])
                recommended_CDM.insert(ProjectConfigFile.CYBERARM_ROI,-1)
                CDM_Global_All_Statistice_Iterative_Budget.append(recommended_CDM)
                if affordable_risk_variable == affordable_risk:
                    break
                minimum_risk_variable = affordable_risk_variable + 1
                reduced_risk_value_iteration_variable = (satisfied_risk_variable - minimum_risk_variable)/(ProjectConfigFile.ITERATION_MODEL_SATISFACTION - model_iteration_index)
                affordable_risk_variable = satisfied_risk_variable - reduced_risk_value_iteration_variable
                continue
            # cyberARM.pop()

            ################################################################## Prepare the output ###################################################
            CDM_Global_id = []
            threat_action_effectiveness_enforced = [[1.0 for t_a in range(len(threat_action_id_list_for_all_assets[asset_index]))]
                                                    for asset_index in range(len(threat_action_id_list_for_all_assets))]

            # print "Threat Action Effectiveness Enforced %s %s" % (threat_action_effectiveness_enforced,threat_action_id_to_position_roll)
            global_enforcement_cost = 0.0
            local_enforcement_cost = [0.0 for i in range(len(asset_list_for_smt))]
            for asset_index in range(len(asset_list_for_smt)):
                # print "******** >>>>>>>>>>>>>>> Asset Index %s" % (asset_index)
                CDM_Global_id.append([])
                sec_control_index = 0
                for sec_control in selected_security_controls[asset_index]:
                    if recommended_CDM[smt_Security_Control_Bool[asset_index][sec_control_index]]:
                        # print " ----  Boolean (%s,%s,%s) : %s" % (smt_Security_Control_Bool[asset_index][sec_control_index],asset_index,sec_control_index,recommended_CDM[smt_Security_Control_Bool[asset_index][sec_control_index]])
                        CDM_Global_id[asset_index].append(security_control_list[sec_control])
                        for threat_action in security_control_list[sec_control].global_asset_threat_action_list[asset_index]:
                            # print "Remedied Threat Action %s" % (threat_action)
                            threat_action_effectiveness_enforced[asset_index][threat_action_id_to_position_roll[asset_index][threat_action]] *= (1-security_control_list[sec_control].threat_action_effectiveness[threat_action])
                        local_enforcement_cost[asset_index] += security_control_list[sec_control].investment_cost
                    else:
                        # print " ----  Boolean (SMT Variable --> %s, Asset Id --> %s, Security Control Id --> %s) : Status --> %s" % (smt_Security_Control_Bool[asset_index][sec_control_index],asset_index, sec_control_index, recommended_CDM[smt_Security_Control_Bool[asset_index][sec_control_index]])
                        pass
                    sec_control_index += 1
            global_enforcement_cost = sum(local_enforcement_cost)
            # print "Threat Action Effectiveness %s" % (threat_action_effectiveness_enforced)
            # print CDM_Global_id

            # print "########################################### Prepare Threat Success #####################################################"
            threat_success_final = [[1 for j in range(len(threat_id_for_all_assets[i]))] for i in range(len(threat_id_for_all_assets))]
            global_residual_risk_final = 0.0
            for asset_index in range(len(threat_id_for_all_assets)):
                threat_id_index = 0
                for threat_id in threat_id_for_all_assets[asset_index]:
                    # print "****** Threat ID %s : %s **********" % (threat_id, threat_list[threat_id].global_asset_threat_action[asset_index])
                    threat_action_index = 0
                    for threat_action in threat_list[threat_id].global_asset_threat_action[asset_index]:
                        # print "************** Threat Action (ID: %s, Position: %s, Threat Action Survival: %s) ********************" % (threat_action,threat_action_id_to_position_roll[asset_index][threat_action],
                        #                                                                          threat_action_effectiveness_enforced[asset_index][threat_action_id_to_position_roll[asset_index][threat_action]])
                        threat_success_final[asset_index][threat_id_index] *= (1-(threat_action_effectiveness_enforced[asset_index][threat_action_id_to_position_roll[asset_index][threat_action]]*
                                                                               threat_list[threat_id].global_asset_threat_action_prob[asset_index][threat_action_index]))
                        threat_action_index += 1
                    threat_success_final[asset_index][threat_id_index] *= (1-threat_list[threat_id].ignored_threat_action[asset_index])
                    threat_success_final[asset_index][threat_id_index] = (1-threat_success_final[asset_index][threat_id_index])*threat_list[threat_id].threat_effect[asset_index]
                    global_residual_risk_final += threat_success_final[asset_index][threat_id_index]
                    # print "****** Threat ID %s : %s **********" % (threat_id, threat_success_final[asset_index][threat_id_index])
                    threat_id_index += 1
            # print "Global Residual Risk %s" % (global_residual_risk_final)
            # print "From SMT %s" % (recommended_CDM[smt_Global_Residual_Risk])

            CDM_Global = []
            for asset_index in range(len(CDM_Global_id)):
                # print CDM_Global.append([])
                asset_name_current = asset_list_for_smt[asset_index][0]
                for security_control_obj in CDM_Global_id[asset_index]:
                    row = {}
                    row['asset_name'] = asset_name_current
                    row['sc_name']=security_control_obj.sc_name
                    row['sc_function'] =ProjectConfigFile.ID_TO_SECURITY_FUNCTION[security_control_obj.sc_function]
                    row['en_level'] =ProjectConfigFile.ID_TO_ENFORCEMENT_LEVEL[security_control_obj.en_level]
                    row['kc_phase'] =ProjectConfigFile.ID_TO_KILL_CHAIN_PHASE[security_control_obj.kc_phase]
                    CDM_Global.append(row)
            ########################################################### End of the dataset of the grid view #################################

            ########################################################### Capture The ROI ####################################################
            roi_statistics = {}
            roi_statistics[ProjectConfigFile.IMPOSED_RISK] = round(global_estimated_risk,3)
            roi_statistics[ProjectConfigFile.TOTAL_IMPLEMENTATION_COST] = round(global_enforcement_cost,3)
            roi_statistics[ProjectConfigFile.RESIDUAL_RISK] = round(global_residual_risk_final,3)
            roi_statistics[ProjectConfigFile.MITIGATED_RISK] = (roi_statistics[ProjectConfigFile.IMPOSED_RISK] - roi_statistics[ProjectConfigFile.RESIDUAL_RISK])
            roi_statistics[ProjectConfigFile.ROI] = (roi_statistics[ProjectConfigFile.MITIGATED_RISK]-roi_statistics[ProjectConfigFile.TOTAL_IMPLEMENTATION_COST]
                                                     )/roi_statistics[ProjectConfigFile.TOTAL_IMPLEMENTATION_COST]
            ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write(
                "Imposed Risk %s ROI: %s, Total Implementation Cost: %s, Residual Risk: %s, Mitigated Risk: %s\n\n" %
                (roi_statistics[ProjectConfigFile.IMPOSED_RISK], roi_statistics[ProjectConfigFile.ROI],
                 roi_statistics[ProjectConfigFile.TOTAL_IMPLEMENTATION_COST],
                 roi_statistics[ProjectConfigFile.RESIDUAL_RISK],
                 roi_statistics[ProjectConfigFile.MITIGATED_RISK]))
            Utitilities.appendStatsInFile([number_of_unique_asset,global_estimated_risk,
                                           roi_statistics[ProjectConfigFile.RESIDUAL_RISK],
                                           roi_statistics[ProjectConfigFile.TOTAL_IMPLEMENTATION_COST],
                                           time_required_specific])
            ########################################################### End of Capture of The Risk ####################################################

            ########################################################### Hold the Risk #######################################################
            risk_all = []
            for asset_index in range(len(threat_id_for_all_assets)):
                risk_all.append({})
                risk_all[asset_index]['asset_name'] = asset_list_for_smt[asset_index][0]
                risk_all[asset_index]['max_risk'] = 0
                risk_all[asset_index]['res_risk'] = 0
                risk_all[asset_index]['imp_cost'] = round(local_enforcement_cost[asset_index],3)
                threat_id_index = 0
                all_threats = []
                for threat in threat_id_for_all_assets[asset_index]:
                    specific_threat_information = {}
                    specific_threat_information['threat_action_name'] = threat_list[threat].threat_name
                    specific_threat_information['risk_ta'] = round(threat_success_final[asset_index][threat_id_index],3)
                    specific_threat_information['prev_risk'] = round(threat_list[threat].maximum_risk[asset_index],3)
                    risk_all[asset_index]['max_risk'] += threat_list[threat].maximum_risk[asset_index]
                    risk_all[asset_index]['res_risk'] += threat_success_final[asset_index][threat_id_index]
                    all_threats.append(specific_threat_information)
                    threat_id_index += 1
                risk_all[asset_index]['max_risk'] = round(risk_all[asset_index]['max_risk'],3)
                risk_all[asset_index]['res_risk'] = round(risk_all[asset_index]['res_risk'],3)
                risk_all[asset_index]['threat_list'] = all_threats
            ########################################################### End Hold Risk #######################################################

            ########################################################### Return Value ########################################################
            CDM_Global_All_Statistice = []
            # CDM_Global_All_Statistice.insert(ProjectConfigFile.CYBERARM_CDM_MATRIX,CDM_Global)
            # CDM_Global_All_Statistice.insert(ProjectConfigFile.CYBERARM_RISK,risk_All)
            # CDM_Global_All_Statistice.insert(ProjectConfigFile.CYBERARM_ROI,roi_row)
            CDM_Global_All_Statistice.insert(ProjectConfigFile.CYBERARM_CDM_MATRIX, CDM_Global)
            CDM_Global_All_Statistice.insert(ProjectConfigFile.CYBERARM_RISK,risk_all)
            CDM_Global_All_Statistice.insert(ProjectConfigFile.CYBERARM_ROI,roi_statistics)
            CDM_Global_All_Statistice_Iterative_Budget.append(CDM_Global_All_Statistice)
            satisfied_risk_variable = roi_statistics[ProjectConfigFile.RESIDUAL_RISK]
            reduced_risk_value_iteration_variable = (satisfied_risk_variable - minimum_risk_variable)/(ProjectConfigFile.ITERATION_MODEL_SATISFACTION - model_iteration_index)
            affordable_risk_variable = satisfied_risk_variable - reduced_risk_value_iteration_variable
        ProjectConfigFile.OUTPUT_FILE_NAME_ITERATIVE_SEARCH.write(
            "Time Required For Specific Cost Iteration %s\n\n" % (cost_iteration_total_time))

        CDM_Global_All_Statistice_Iterative.append(CDM_Global_All_Statistice_Iterative_Budget)
        """Send in this format Assets,Total Risk,Budget,Residual Risk,Time,Threat Elimination,Security Controls"""
        Utitilities.appendTimeRiskStatsInFile([number_of_unique_asset,global_estimated_risk,budget_variable,satisfied_risk_variable,cost_iteration_total_time,
                                               ProjectConfigFile.RISK_ELIMINATION,Utitilities.determineSizeCandidateSet(selected_security_controls)])
        budget_variable += increase_budget
    return CDM_Global_All_Statistice_Iterative


