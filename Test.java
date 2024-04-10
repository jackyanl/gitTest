package org.inspur.common.jwt;

import io.jsonwebtoken.*;
import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;

/**
 * jwt工具类
 */
@Slf4j
public class JwtHelper {
    // token时效：365天
    private static long tokenExpiration = 365 * 24 * 60 * 60 * 1000;
    private static String tokenSignKey = "123456";   //生成签名时密钥

    //根据用户id和用户名称生成token字符串
    public static String createToken(Long userId, String userName){
        String token = Jwts.builder()
                // 分类
                .setSubject("AUTH-USER")
                // 有效时长
                .setExpiration(new Date( System.currentTimeMillis() + tokenExpiration))
                // 有效载荷
                .claim("userId",userId)
                .claim("userName",userId)
                // 签名部分
                .signWith(SignatureAlgorithm.HS512, tokenSignKey)
                .compressWith(CompressionCodecs.GZIP)
                .compact();
        return token;
    }

    // 从生成token中获取用户id
    public static Long getUserId(String token){
        Long userId = null;
    try {
            if (StringUtils.isEmpty(token)) {
                log.error("token为空");
                return null;
             }
            Jws<Claims> claimsJwts = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token);
            Claims claims = claimsJwts.getBody();
            userId = (Long) claims.get("userId");
        } catch (Exception e) {
           log.error("从token获取userId失败："+e);
            }
            return userId;
    }
    // 从token获取userName
    public static String getUserName(String token){
        String userName = null;
        try {
            if (StringUtils.isEmpty(token)) {
                log.error("token为空");
                return null;
            }
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token);
            Claims claims = claimsJws.getBody();
            userName = (String) claims.get("userName");
        } catch (Exception e) {
           log.error("从token获取userName失败"+e);
        }
            return userName;
    }

    public static void main(String[] args) {
        System.out.println(new Date(System.currentTimeMillis()));
        System.out.println(new Date(System.currentTimeMillis() + tokenExpiration));
    }
}
