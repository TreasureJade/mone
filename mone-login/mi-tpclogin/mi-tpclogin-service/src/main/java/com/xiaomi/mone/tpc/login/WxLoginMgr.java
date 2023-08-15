package com.xiaomi.mone.tpc.login;

import com.alibaba.nacos.api.config.annotation.NacosValue;
import com.alibaba.nacos.common.utils.MapUtils;
import com.google.common.collect.Maps;
import com.xiaomi.mone.tpc.api.service.UserFacade;
import com.xiaomi.mone.tpc.common.param.UserRegisterParam;
import com.xiaomi.mone.tpc.dao.entity.AccountEntity;
import com.xiaomi.mone.tpc.dao.impl.AccountDao;
import com.xiaomi.mone.tpc.login.common.enums.UserTypeEnum;
import com.xiaomi.mone.tpc.login.common.util.MD5Util;
import com.xiaomi.mone.tpc.login.common.vo.AuthAccountVo;
import com.xiaomi.mone.tpc.login.vo.AuthUserVo;
import com.xiaomi.mone.tpc.util.TokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.net.URLEncoder;
import java.util.Map;

/**
 * @author caobaoyu
 * @description:
 * @date 2023-08-15 15:33
 */
@Slf4j
public class WxLoginMgr extends LoginMgr {
    @Resource
    private AccountDao accountDao;
    @NacosValue("${wx.appId:''}")
    private String wxAppId;
    @NacosValue("${wx.appSecret:''}")
    private String wxAppSecret;

    @Resource
    private RestTemplate restTemplate;

    @Autowired
    private UserFacade userFacade;

    @Override
    public AuthAccountVo buildAuth2LoginInfo(String pageUrl, String vcode, String state) throws Exception {
        AuthAccountVo info = new AuthAccountVo();
        info.setName("wx");
        info.setDesc("wx扫码注册登陆");
        info.setUrl(this.buildAuthUrl(pageUrl, state));
        return info;
    }

    public String buildAuthUrl(String pageUrl, String state) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(getAuthUrl()).append("&redirect_uri=").append(URLEncoder.encode(pageUrl, "UTF-8"));
        if (StringUtils.isNotBlank(state)) {
            sb.append("&state").append(state);
        }
        sb.append("#wechat_redirect");
        return sb.toString();
    }

    @Override
    public AuthUserVo getUserVo(String code, String pageUrl, String vcode, String state) {
        String tokenReqUrl = getTokenUrl() + "&code=" + code;
        ResponseEntity<Map> forEntity = restTemplate.getForEntity(tokenReqUrl, Map.class);
        Map body = forEntity.getBody();
        if (MapUtils.isEmpty(body)) {
            log.error("wx没有拿到用户信息,forEntity={}", forEntity);
            return null;
        }

        String accessToken = body.get("access_token").toString();
        String openId = body.get("openId").toString();
        if (StringUtils.isBlank(accessToken) || StringUtils.isBlank(openId)) {
            log.error("accessToken or openId is null,accessToken:{},openId:{}", accessToken, openId);
            return null;
        }
        // 微信解出用户信息
        Map<String, Object> userInfo = getUserInfo(accessToken, openId);
        if (MapUtils.isEmpty(userInfo)) {
            return null;
        }
        AuthUserVo userVo = buildAuthUserInfo(userInfo);
        if (ObjectUtils.isEmpty(userVo)) {
            log.error("getUserInfo error");
            return null;
        }

        AccountEntity entity = accountDao.getOneByAccount(userVo.getAccount(), userVo.getUserType());
        userVo.setExprTime(Integer.parseInt(body.get("expires_in").toString()));
        userVo.setToken(TokenUtil.createToken(userVo.getExprTime(), userVo.getAccount(), userVo.getUserType()));

        // 之前已经落过库了
        if (ObjectUtils.isNotEmpty(entity)) {
            log.info("wx user:{} login success", entity.getAccount());
            return userVo;
        }

        String unionId = userInfo.get("unionid").toString();
        // 没落过库，走注册流程
        entity = new AccountEntity();
        entity.setType(userVo.getUserType());
        entity.setAccount(userVo.getAccount());
        entity.setName(userVo.getName());
        entity.setPwd(MD5Util.md5(openId + unionId));
        boolean result = accountDao.insert(entity);
        if (!result) {
            log.error("accountDao.insert error");
            return null;
        }
        UserRegisterParam registerParam = new UserRegisterParam();
        registerParam.setAccount(entity.getAccount());
        registerParam.setUserType(userVo.getUserType());
        userFacade.register(registerParam);

        return userVo;
    }

    @Override
    public String getSource() {
        return "wechat";
    }

    @Override
    public String getAuthUrl() {
        return "https://open.weixin.qq.com/connect/qrconnect" + "?appid=" + wxAppId + "&response_type=code" + "&scope=snsapi_login";
    }

    @Override
    public String getTokenUrl() {
        return "https://api.weixin.qq.com/sns/oauth2/access_token" + "?appid=" + wxAppId +
                "&secret=" + wxAppSecret +
                "&grant_type=authorization_code";
    }

    @Override
    public String getUserUrl() {
        return "https://api.weixin.qq.com/sns/userinfo";
    }

    @Override
    public String getEmailUrl() {
        return null;
    }

    private Map getUserInfo(String accessToken, String openId) {
        String userReq = getUserUrl() + "?access_token=" + accessToken
                + "&openid" + openId;
        ResponseEntity<Map> forEntity = restTemplate.getForEntity(userReq, Map.class);
        Map body = forEntity.getBody();
        if (MapUtils.isEmpty(body)) {
            log.error("wx获取用户信息失败,forEntity:{}", forEntity);
            return Maps.newHashMap();
        }
        return body;

    }

    private AuthUserVo buildAuthUserInfo(Map<String, Object> wxParam) {
        AuthUserVo vo = new AuthUserVo();
        String openid = wxParam.get("openid").toString();
        String nickName = wxParam.get("nickname").toString();
        vo.setAccount(openid);
        vo.setUserType(UserTypeEnum.WX_TYPE.getCode());
        vo.setName(nickName);
        return vo;
    }

}
