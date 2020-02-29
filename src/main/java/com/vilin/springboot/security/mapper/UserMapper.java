package com.vilin.springboot.security.mapper;

import com.vilin.springboot.security.entity.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Component;

@Component
public interface UserMapper {

    @Select("SELECT * FROM user_auth WHERE username=#{username}")
    User findByUserName(@Param("username") String username);

}
