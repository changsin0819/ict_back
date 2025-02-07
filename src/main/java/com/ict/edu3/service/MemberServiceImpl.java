package com.ict.edu3.service;

import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ict.edu3.mapper.MembersMapper;
import com.ict.edu3.vo.MembersVO;

@Service
public class MemberServiceImpl implements MemberService{
    @Autowired
    private MembersMapper memberMapper;

    @Override
    public List<MembersVO> getMemberList() {
        return memberMapper.findAllMembers();
    }

    @Override
    public MembersVO getMemberDetail(String m_id) {
        return memberMapper.findUserById(m_id);
    }

    @Override
    public void saveRefreshToken(String user_id, String refresh_token, Date expiry_date) {
        try {
            memberMapper.saveRefreshToken(user_id, refresh_token, expiry_date);
        } catch (Exception e) {
           System.out.println("토큰 저장 오류 : " + e);
        }
    } 

    @Override
    public String findRefreshToken(String userId) {
        return memberMapper.findRefreshToken(userId);
    }

    @Override
    public void deleteRefreshToken(String userId) {
        memberMapper.deleteRefreshToken(userId);
    }

    @Override
    public void insertUser(MembersVO mvo) {
        memberMapper.insertUser(mvo);
    }
}
