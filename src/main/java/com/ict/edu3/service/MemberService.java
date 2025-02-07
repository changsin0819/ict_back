package com.ict.edu3.service;

import java.util.Date;
import java.util.List;
import com.ict.edu3.vo.MembersVO;

public interface MemberService {
	public List<MembersVO> getMemberList();
    public MembersVO getMemberDetail(String id);

    void saveRefreshToken(String userId, String refresh_token, Date expiry_date);
    String findRefreshToken(String userId);
    void deleteRefreshToken(String userId);
    void insertUser(MembersVO mvo);
}
