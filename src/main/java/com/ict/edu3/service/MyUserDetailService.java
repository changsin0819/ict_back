package com.ict.edu3.service;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ict.edu3.mapper.MembersMapper;
import com.ict.edu3.vo.MembersVO;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MyUserDetailService implements UserDetailsService{

    private final MembersMapper membersMapper;

    // id를 받아서 members 테이블에 해당 id가 있는지 찾는다.
    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        MembersVO member = membersMapper.findUserById(userId);

        return new User(member.getM_id(), member.getM_pw(), new ArrayList<>());
    }

    // 정보를 받아서 회원가입
    public void registerUser(MembersVO mvo){
        membersMapper.insertUser(mvo);
    }

}
