package com.ict.edu3.mapper;

import java.util.Date;
import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.ict.edu3.vo.MembersVO;

@Mapper
public interface MembersMapper {
    @Select("Select * from members where m_id = #{m_id}")
    MembersVO findUserById(@Param("m_id")String m_id);

    @Insert("insert into members(m_id, m_pw, m_name, m_age, sns_provider, sns_email_naver, sns_email_kakao, sns_email_google)  " +
            "values(#{m_id}, #{m_pw}, #{m_name}, #{m_age}, #{sns_provider}, #{sns_email_naver}, #{sns_email_kakao}, #{sns_email_google})" )
    void insertUser(MembersVO mvo);

    @Select("SELECT * FROM members")
    List<MembersVO> findAllMembers();

    @Insert("INSERT INTO refresh_tokens(user_id, refresh_token, expiry_date)  " +
            "values (#{user_id}, #{refresh_token}, #{expiry_date})  " +
            "on duplicate key update refresh_token = #{refresh_token}, expiry_date = #{expiry_date} ")
    void saveRefreshToken(@Param("user_id")String user_id,@Param("refresh_token") String refresh_token,@Param("expiry_date") Date expiry_date);

    @Select("select refresh_token from refresh_tokens where user_id=#{user_id}")
    String findRefreshToken(String user_id);

    @Delete("delete from refresh_tokens where user_id=#{user_id}")
    void deleteRefreshToken(String user_id);
}
