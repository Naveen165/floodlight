/**
 *    Copyright 2011, Big Switch Networks, Inc.
 *    Originally created by David Erickson, Stanford University
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.staticflowentry.web;

import java.io.IOException;
import java.util.Map;


import org.restlet.resource.Delete;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.annotations.LogMessageCategory;
import net.floodlightcontroller.core.annotations.LogMessageDoc;
import net.floodlightcontroller.staticflowentry.StaticFlowEntries;
import net.floodlightcontroller.staticflowentry.StaticFlowEntryPusher;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.util.MatchUtils;

/**
 * Pushes a static flow entry to the storage source
 * @author alexreimers
 *
 */
@LogMessageCategory("Static Flow Pusher")
public class StaticFlowEntryPusherResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(StaticFlowEntryPusherResource.class);

	private final int STATE_NO_ERROR = 0;
	private final int STATE_ETH_TYPE_ERROR = 1;
	private final int STATE_IP_PROTO_ERROR = 2;
	private final int STATE_ICMP6_TYPE_ERROR = 3;
	private final int STATE_MULTIPLE_TP_PORT_ERROR = 4;
	private final int STATE_IPv_CONFLICT_ERROR = 5;

	/**
	 * Validates if all the mandatory fields are set properly while adding an IPv6 flow
	 * @param Map containing the fields of the flow
	 * @return state indicating whether a flow is valid or not
	 */
	private int checkFlow(Map<String, Object> rows) {    
	
		boolean icmp_code = false;
		boolean icmp6_type = false;
		boolean nd_target = false;
		boolean nd_sll = false;
		boolean nd_tll = false; 
		boolean ip6 = false;
		boolean ip4 = false;
		boolean tp_port = false;

		int eth_type = -1;
		int nw_protocol = -1;
		int icmp_type = -1;

		//Determine the dl_type if set
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_DL_TYPE)) {
			if (((String) rows.get(StaticFlowEntryPusher.COLUMN_DL_TYPE)).startsWith("0x")) {
				eth_type = Integer.parseInt(((String) rows.get(StaticFlowEntryPusher.COLUMN_DL_TYPE)).replaceFirst("0x", ""), 16);
			} else {
				eth_type = Integer.parseInt((String) rows.get(StaticFlowEntryPusher.COLUMN_DL_TYPE));
			}
			if (eth_type == 0x86dd) { /* or 34525 */
				ip6 = true;
			} else if (eth_type == 0x800 || /* or 2048 */
					eth_type == 0x806 || /* or 2054 */
					eth_type == 0x8035) { /* or 32821*/
				ip4 = true;
			}	

		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_NW_DST) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_NW_SRC)) {
			if (!ip4) {
				return STATE_ETH_TYPE_ERROR;
			}
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ICMP_CODE) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_ICMP_TYPE) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_ARP_DHA) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_ARP_SHA) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_ARP_SPA) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_ARP_DPA) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_ARP_OPCODE)) {
			ip4 = true;
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_IPV6_FLOW_LABEL) || 
				rows.containsKey(StaticFlowEntryPusher.COLUMN_NW6_SRC) ||
				rows.containsKey(StaticFlowEntryPusher.COLUMN_NW6_DST)) {
			if (!ip6) {
				return STATE_ETH_TYPE_ERROR;
			}
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_NW_PROTO)) {
			if (!(ip4 || ip6)) {//sanjivini1
				return STATE_ETH_TYPE_ERROR;
			}
			if (((String) rows.get(StaticFlowEntryPusher.COLUMN_NW_PROTO)).startsWith("0x")) {
				nw_protocol = Integer.parseInt(((String) rows.get(StaticFlowEntryPusher.COLUMN_NW_PROTO)).replaceFirst("0x", ""), 16);
			} else {
				nw_protocol = Integer.parseInt((String) rows.get(StaticFlowEntryPusher.COLUMN_NW_PROTO));
			}
		}
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ICMP_CODE)) {
			icmp_code = true;
			ip4 = true;
		}
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ICMP_TYPE)) {
			ip4 = true;
			if (((String) rows.get(StaticFlowEntryPusher.COLUMN_ICMP_TYPE)).startsWith("0x")) {
				icmp_type = Integer.parseInt(((String) rows.get(StaticFlowEntryPusher.COLUMN_ICMP_TYPE)).replaceFirst("0x", ""), 16);
			} else {
				icmp_type = Integer.parseInt((String) rows.get(StaticFlowEntryPusher.COLUMN_ICMP_TYPE));
			}
		}
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ICMP6_CODE)) {
			icmp_code = true;
			ip6 = true;
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ICMP6_TYPE)) {
			icmp6_type = true;
			ip6 = true;
			if (((String) rows.get(StaticFlowEntryPusher.COLUMN_ICMP6_TYPE)).startsWith("0x")) {
				icmp_type = Integer.parseInt(((String) rows.get(StaticFlowEntryPusher.COLUMN_ICMP6_TYPE)).replaceFirst("0x", ""), 16);
			} else {
				icmp_type = Integer.parseInt((String) rows.get(StaticFlowEntryPusher.COLUMN_ICMP6_TYPE));
			}
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ND_SLL)) {
			nd_sll = true;
			ip6 = true;
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ND_TLL)) {
			nd_tll = true;
			ip6 = true;
		}
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_ND_TARGET)) {
			nd_target = true;
			ip6 = true;
		}   
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_TCP_SRC)
				|| rows.containsKey(StaticFlowEntryPusher.COLUMN_TCP_DST)) {
					
			if ((nw_protocol == -1) || (nw_protocol != 6))
				return STATE_IP_PROTO_ERROR;
			tp_port = true;
		}
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_UDP_SRC)
				|| rows.containsKey(StaticFlowEntryPusher.COLUMN_UDP_DST)) {
			
			if (tp_port) {
				return STATE_MULTIPLE_TP_PORT_ERROR;
			}
			if ((nw_protocol == -1) || (nw_protocol != 17))
				return STATE_IP_PROTO_ERROR;
			tp_port = true;
		}
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_SCTP_SRC)
				|| rows.containsKey(StaticFlowEntryPusher.COLUMN_SCTP_DST)) {
			
			if (tp_port) {
				return STATE_MULTIPLE_TP_PORT_ERROR;
			}
			if ((nw_protocol == -1) || (nw_protocol != 132))
				return STATE_IP_PROTO_ERROR;
			tp_port = true;
		}
		
		if (rows.containsKey(StaticFlowEntryPusher.COLUMN_TP_SRC)
				|| rows.containsKey(StaticFlowEntryPusher.COLUMN_TP_DST)) {
			if (tp_port) {
				return STATE_MULTIPLE_TP_PORT_ERROR;
			}
			if (nw_protocol == -1) 
				return STATE_IP_PROTO_ERROR;
		}

		if (icmp_type != -1 || icmp_code) {
			if ((nw_protocol == -1)
					|| !(((nw_protocol == 0x3A) && ip6) || ((nw_protocol == 1) && ip4))) { 
					//invalid nw_proto 
					return STATE_IP_PROTO_ERROR;
			}
		}

		if (nd_sll || nd_tll || nd_target) {
			if (icmp6_type) {
				//icmp_type must be set to 135/136 to set ipv6_nd_target
				if (nd_target) {
					if (!(icmp_type == 135 || icmp_type == 136)) { /* or 0x87 / 0x88 */
						//invalid icmp6_type
						return STATE_ICMP6_TYPE_ERROR;
					}
				}
				//icmp_type must be set to 136 to set ipv6_nd_tll
				else if (nd_tll) {
					if (!(icmp_type == 136)) {
						//invalid icmp6_type
						return STATE_ICMP6_TYPE_ERROR;
					}
				}
				//icmp_type must be set to 135 to set ipv6_nd_sll
				else if (nd_sll) {
					if (!(icmp_type == 135)) {
						//invalid icmp6_type
						return STATE_ICMP6_TYPE_ERROR;
					}
				}
			}
			else {
				//icmp6_type not set
				return STATE_ICMP6_TYPE_ERROR;
			}
		}

		int result = checkActions(rows);

		if ((ip4 == true && ip6 == true) || (result == -1) ||
				(result == 1 && ip6 == true) || (result == 2 && ip4 == true)) {
			//ipv4 & ipv6 conflict
			return STATE_IPv_CONFLICT_ERROR;
		}

		return STATE_NO_ERROR;
	}

	/**
	 * Validates actions/instructions
	 * 
	 * -1 --> IPv4/IPv6 conflict
	 * 0 --> no IPv4 or IPv6 actions
	 * 1 --> IPv4 only actions
	 * 2 --> IPv6 only actions
	 * 
	 * @param Map containing the fields of the flow
	 * @return state indicating whether a flow is valid or not
	 */
	public static int checkActions(Map<String, Object> entry) {

		boolean ip6 = false;
		boolean ip4 = false;
		String actions = null;

		if (entry.containsKey(StaticFlowEntryPusher.COLUMN_ACTIONS) || 
				entry.containsKey(StaticFlowEntryPusher.COLUMN_INSTR_APPLY_ACTIONS) ||
				entry.containsKey(StaticFlowEntryPusher.COLUMN_INSTR_WRITE_ACTIONS)) {
			if (entry.containsKey(StaticFlowEntryPusher.COLUMN_ACTIONS)) {
				actions = (String) entry.get(StaticFlowEntryPusher.COLUMN_ACTIONS);
			}
			else if (entry.containsKey(StaticFlowEntryPusher.COLUMN_INSTR_APPLY_ACTIONS)) {
				actions = (String) entry.get(StaticFlowEntryPusher.COLUMN_INSTR_APPLY_ACTIONS);
			}
			else if (entry.containsKey(StaticFlowEntryPusher.COLUMN_INSTR_WRITE_ACTIONS)) {
				actions = (String) entry.get(StaticFlowEntryPusher.COLUMN_INSTR_WRITE_ACTIONS);
			}

			if (actions.contains(MatchUtils.STR_ICMPV6_CODE) || actions.contains(MatchUtils.STR_ICMPV6_TYPE) ||
					actions.contains(MatchUtils.STR_IPV6_DST) || actions.contains(MatchUtils.STR_IPV6_SRC) || 
					actions.contains(MatchUtils.STR_IPV6_FLOW_LABEL) || actions.contains(MatchUtils.STR_IPV6_ND_SSL) ||
					actions.contains(MatchUtils.STR_IPV6_ND_TARGET) || actions.contains(MatchUtils.STR_IPV6_ND_TTL)) {
				ip6 = true;
			}
			if (actions.contains(MatchUtils.STR_NW_SRC) || actions.contains(MatchUtils.STR_NW_DST) || 
					actions.contains(MatchUtils.STR_ARP_OPCODE) || actions.contains(MatchUtils.STR_ARP_SHA) || 
					actions.contains(MatchUtils.STR_ARP_DHA) || actions.contains(MatchUtils.STR_ARP_SPA) || 
					actions.contains(MatchUtils.STR_ARP_DPA) || actions.contains(MatchUtils.STR_ICMP_CODE) || 
					actions.contains(MatchUtils.STR_ICMP_TYPE)) {
				ip4 = true;
			}
		}

		if (ip6 == false && ip4 == false) {
			return 0; // no actions involving ipv4 or ipv6
		} else if (ip6 == false && ip4 == true) {
			return 1; //ipv4
		} else if (ip6 == true && ip4 == false) {
			return 2; //ipv6
		} else {
			return -1; // conflict of ipv4 and ipv6 actions
		}
	}

	/**
	 * Takes a Static Flow Pusher string in JSON format and parses it into
	 * our database schema then pushes it to the database.
	 * @param fmJson The Static Flow Pusher entry in JSON format.
	 * @return A string status message
	 */
	@Post
	@LogMessageDoc(level="ERROR",
	message="Error parsing push flow mod request: {request}",
	explanation="An invalid request was sent to static flow pusher",
	recommendation="Fix the format of the static flow mod request")
	public String store(String fmJson) {
		IStorageSourceService storageSource =
				(IStorageSourceService)getContext().getAttributes().
				get(IStorageSourceService.class.getCanonicalName());

		Map<String, Object> rowValues;
		try {
			rowValues = StaticFlowEntries.jsonToStorageEntry(fmJson);
			String status = null;

			int state = checkFlow(rowValues);
			
			if (state == STATE_ETH_TYPE_ERROR) {
				status = "Warning: Invalid/Missing eth_type! Must specify eth_type of IPv4/IPv6 to " +
						"match on IPv4/IPv6 fields! The flow has been discarded.";
				log.error(status);
			} else if (state == STATE_IP_PROTO_ERROR) {
				status = "Warning! Invalid/Missing ip_proto to match! The flow has been discarded.";
				log.error(status);
			} else if (state == STATE_ICMP6_TYPE_ERROR) {
				status = "Warning! Invalid/Missing icmp6_type to match! The flow has been discarded.";
				log.error(status);
			} else if (state == STATE_MULTIPLE_TP_PORT_ERROR) {
				status = "Warning! Multiple tp_port types set! The flow has been discarded.";
				log.error(status);
			} else if (state == STATE_IPv_CONFLICT_ERROR) {
				status = "Warning! IPv4 & IPv6 fields cannot be specified in the same flow! The flow has been discarded.";
				log.error(status);
			} else if (state == STATE_NO_ERROR) {
				status = "Entry pushed";            
				storageSource.insertRowAsync(StaticFlowEntryPusher.TABLE_NAME, rowValues);
			}
			return ("{\"status\" : \"" + status + "\"}");
		} catch (IOException e) {
			log.error("Error parsing push flow mod request: " + fmJson, e);
			return "{\"status\" : \"Error! Could not parse flod mod, see log for details.\"}";
		}        
	}

	@Delete
	@LogMessageDoc(level="ERROR",
	message="Error deleting flow mod request: {request}",
	explanation="An invalid delete request was sent to static flow pusher",
	recommendation="Fix the format of the static flow mod request")
	public String del(String fmJson) {
		IStorageSourceService storageSource =
				(IStorageSourceService)getContext().getAttributes().
				get(IStorageSourceService.class.getCanonicalName());
		String fmName = null;
		if (fmJson == null) {
			return "{\"status\" : \"Error! No data posted.\"}";
		}
		try {
			fmName = StaticFlowEntries.getEntryNameFromJson(fmJson);
			if (fmName == null) {
				return "{\"status\" : \"Error deleting entry, no name provided\"}";
			}
		} catch (IOException e) {
			log.error("Error deleting flow mod request: " + fmJson, e);
			return "{\"status\" : \"Error deleting entry, see log for details\"}";
		}

		storageSource.deleteRowAsync(StaticFlowEntryPusher.TABLE_NAME, fmName);
		return "{\"status\" : \"Entry " + fmName + " deleted\"}";
	}
}
