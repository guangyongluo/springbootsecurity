package com.vilin.springboot.security.mapper;

import org.apache.ibatis.annotations.Param;
import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import java.util.Date;

public interface PersistentTokenMapper extends PersistentTokenRepository {

    void createNewToken(PersistentRememberMeToken token);

    void updateToken(@Param("series") String series, @Param("tokenValue") String tokenValue, @Param("lastUsed") Date lastUsed);

    PersistentRememberMeToken getTokenForSeries(String series);

    void removeUserTokens(String series);
}
