/*
 *  Copyright 2020 Xiaomi
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package com.xiaomi.youpin.tesla.file.server.bootstrap;

import com.google.common.collect.Lists;
import com.xiaomi.youpin.tesla.file.server.common.Config;
import com.xiaomi.youpin.tesla.file.server.common.Cons;
import com.xiaomi.youpin.tesla.file.server.common.FileServerVersion;
import com.xiaomi.youpin.tesla.file.server.common.UserSecretConfig;
import com.xiaomi.youpin.tesla.file.server.server.FileServer;
import com.xiaomi.youpin.tesla.file.server.service.BaseService;
import com.xiaomi.youpin.tesla.file.server.service.CleanService;
import com.xiaomi.youpin.tesla.file.server.service.ScheduleService;
import lombok.extern.slf4j.Slf4j;

/**
 * @author goodjava@qq.com
 */
@Slf4j
public class FileServerBootstrap {

    private static final String DEFAULT_USER_SECRET_CONFIG_PATH = "/fsserver/user/user-secret.conf";

    public static void main(String... args) {
        // 初始化用户配置
        String configPath = Config.ins().get("userpath", DEFAULT_USER_SECRET_CONFIG_PATH);
        UserSecretConfig.loadConfig(configPath);
        log.info("Initialized UserSecretConfig with path: {}", configPath);

        // 启动服务器
        int port = Integer.parseInt(Cons.SERVER_PORT);
        log.info("{} start {}", new FileServerVersion(), port);
        FileServer server = new FileServer();
        server.setPort(port);
        new ScheduleService(Lists.newArrayList(new CleanService(BaseService.DATAPATH, Cons.CLEAN_NUM))).run();
        server.run();
    }

}
