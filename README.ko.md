# Android Keenadu Auto Scanner

Android 태블릿(ADB 연결)이 감지되면 자동으로 Keenadu IOC를 검사합니다.

## 요구사항
- Windows
- Python 3.10+
- `adb`가 PATH에서 실행 가능해야 함

## 실행
```powershell
python monitor_keenadu.py
```

재부팅 기반 AK_CPP 검사 포함(권장):
```powershell
python monitor_keenadu.py --reboot-for-logcat --logcat-seconds 30
```

세부 실행 로그까지 확인:
```powershell
python monitor_keenadu.py --verbose --command-log-file logs\\keenadu_cmdlog.json
```

## 포함된 핵심 검사
- 검사 방법 1: `logcat`에서 `AK_CPP` 태그 탐지
- 검사 방법 2: `dumpsys activity broadcasts`에서
  - `com.action.SystemOptimizeService`
  - `com.action.SystemProtectService`
- 검사 방법 3: `service list`에서 BADBOX/Keenadu binder 마커
  - `com.androidextlib.sloth.api.IPServiceM`
  - `com.androidextlib.sloth.api.IPermissionsM`
  - `sloth`

## 추가 IOC 검사
- 감염 샘플 패키지명
- `vndx_10x.jar`/`.dx` 아티팩트
- `libandroid_runtime.so` 및 감염 샘플 APK MD5 매칭
- `libandroid_runtime.so` 정적 문자열 마커(`AKServer`, `AKClient` 등)
- 시스템 앱 무결성(경로 이상/베이스라인 해시 비교)
- 부팅 후 반복 스냅샷(`ps`/`service list`/`broadcasts`) 간헐 마커 탐지
- 네트워크 IOC(`logcat`, `dumpsys connectivity`) C2 도메인 마커 탐지
- OTA/빌드 계보(`getprop`) 이상 징후 검사
- Focus 컴포넌트(FaceID/ContentCenter/AppCenter) 권한/서비스 마커 검사
- 사이드로딩 허용 상태(약한 신호)

## 리포트 상태 의미
- `[EXECUTED][DETECTED]`: 검사 실행 + 마커 탐지됨
- `[EXECUTED][NOT DETECTED]`: 검사 실행 + 마커 미탐지
- `[NOT_EXECUTED]`: 권한/접근/명령 실패로 실제 검사 불가

## 주의
- IOC 매칭 기반 탐지라 미탐/오탐 가능성은 남습니다.
- 모든 검사가 음성이어도 100% 안전을 보장하지 않습니다.
- 최신 IOC 공개 시 `keenadu_iocs.json`을 갱신하세요.

## 실행 예시

### KR 샘플
![KR Sample](KR_sample1.png)

### EU 샘플
![EU Sample](EU_sample1.png)

