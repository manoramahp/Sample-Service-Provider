/*
*  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.identity.sso.agent.saml;

import org.wso2.carbon.identity.sso.agent.util.SSOAgentConfigs;

import javax.servlet.http.HttpSession;
import java.util.Hashtable;
import java.util.Map;

public class SSOAgentSessionManager {
	
	/*
	 * Session Index at the IdP is mapped to the session at the SP so that a single logout request can be handled
	 * by invalidating the SP session mapped to IdP Session Index.
	 */
	private static Map<String, HttpSession> ssoSessions  = new Hashtable<String, HttpSession>();
	
	public static void invalidateSession(String sessionIndex) {
		HttpSession session = ssoSessions.remove(sessionIndex);
		if(session != null){
			session.removeAttribute(SSOAgentConfigs.getSessionBeanName());
		}
	}
	
	public static void addAuthenticatedSession(String idPSessionId, HttpSession session){
		ssoSessions.put(idPSessionId, session);
	}

    static Map<String,HttpSession> getSsoSessions(){
        return ssoSessions;
    }
}
