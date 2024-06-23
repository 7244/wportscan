#include <WITCH/WITCH.h>
#include <WITCH/PR/PR.h>
#include <WITCH/MEM/MEM.h>
#include <WITCH/VEC/VEC.h>
#include <WITCH/STR/STR.h>
#include <WITCH/T/T.h>
#include <WITCH/FS/FS.h>
#include <WITCH/EV/EV.h>
#include <WITCH/NET/TCP/TCP.h>
#include <WITCH/TH/TH.h>
#include <WITCH/IO/print.h>

void _print(uint32_t fdint, const char *format, ...){
  IO_fd_t fd_stdout;
  IO_fd_set(&fd_stdout, fdint);
  va_list argv;
  va_start(argv, format);
  IO_vprint(&fd_stdout, format, argv);
  va_end(argv);
}
#define print(...) _print(FD_OUT, __VA_ARGS__)
#define printe(...) _print(FD_ERR, __VA_ARGS__)

#pragma pack(push, 1)
typedef struct{
  uint32_t src;
  uint32_t dst;
  uint32_t progress;
  uint8_t shift;
}progress_t;
#pragma pack(pop)
progress_t progress_init(const uint32_t src, const uint32_t dst){
  progress_t r;
  r.src = src;
  r.dst = dst;
  r.progress = 0;
  r.shift = 32 - (LOG32(dst - src, 2) - 1);
  return r;
}
f32_t progress_percent(const uint32_t src, const uint32_t dst, const progress_t pro){
  return (f32_t)(pro.src + pro.progress - src) / (dst - src);
}
bool progress_hit(const uint32_t src, const uint32_t dst, const progress_t pro){
  return (pro.src + pro.progress) == pro.dst;
}
uint32_t shake_progress(progress_t *progress){
  uint32_t rpro = bitswap32(progress->progress++);
  rpro = rpro >> progress->shift;
  uint32_t result = progress->src + rpro;
  if(((uint32_t)-1 >> progress->shift) == rpro){
    progress->src += progress->progress;
    progress->shift = 32 - (LOG32(progress->dst - progress->src, 2) - 1);
    progress->progress = 0;
  }
  return result;
}

#pragma pack(push, 1)
typedef struct{
  uint32_t rangesrc;
  uint32_t rangedst;
  progress_t progress;
}ip_t;

typedef struct{
  VEC_t ip;
  VEC_t port; /* uint16_t */
  uint16_t progress;
}addr_t;

typedef struct{
  f64_t savedelay;
  uint8_t exportpath[4096];
  uint8_t outputpath[4096];
  f64_t syndelay;
}pscan_ioable_t;
typedef struct{
  pscan_ioable_t ioable;
  VEC_t addr;

  bool import;
  uint64_t syndelay;
  uint64_t last;
  EV_t listener;
  EV_timer_t evt;
  NET_TCP_t *tcp;
  VEC_t outbuff; /* NET_addr_t */
  TH_mutex_t m;
}pscan_t;
#pragma pack(pop)

typedef bool(*paramcb_t)(pscan_t *, const char *);

bool param_help(pscan_t *pscan, const char *param){
  if(param != 0){
    PR_abort();
  }
  printe("example usage:\n");
  printe("./exe --ip 127.0.0.1 --port 22 --syndelay .5 --savedelay 10\n");
  printe("./exe --ip 192.168.1.0/24 192.168.2.128-192.168.3.0 --port 22 23 80 --export path/to/file --output path/to/file\n");
  printe("./exe --import path/to/file\n");
  return 1;
}

bool param_new(pscan_t *pscan, const char *param){
  if(param != 0){
    PR_abort();
  }
  VEC_handle0(&pscan->addr, 1);
  ((addr_t *)pscan->addr.ptr)[pscan->addr.Current - 1].progress = 0;
  VEC_init(&((addr_t *)pscan->addr.ptr)[pscan->addr.Current - 1].ip, sizeof(ip_t), A_resize);
  VEC_init(&((addr_t *)pscan->addr.ptr)[pscan->addr.Current - 1].port, sizeof(uint16_t), A_resize);
  return 0;
}

bool param_ip(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  addr_t *addr = &((addr_t *)pscan->addr.ptr)[pscan->addr.Current - 1];
  ip_t addrip;
  if(!STR_ischar_digit(param[0])){
    #define d(src_m, dst_m) \
      addrip.rangesrc = src_m; \
      addrip.rangedst = dst_m; \
      addrip.progress = progress_init(src_m, dst_m); \
      VEC_handle(&addr->ip); \
      ((ip_t *)addr->ip.ptr)[addr->ip.Current] = addrip; \
      addr->ip.Current++;
    if(!STR_cmp("APNIC", param)){
      d(0x01000000, 0x02000000);
      d(0x0e000000, 0x0f000000);
      d(0x1b000000, 0x1c000000);
      d(0x24000000, 0x25000000);
      d(0x27000000, 0x28000000);
      d(0x2a000000, 0x2b000000);
      d(0x31000000, 0x32000000);
      d(0x3a000000, 0x3b000000);
      d(0x3b000000, 0x3c000000);
      d(0x3c000000, 0x3d000000);
      d(0x3d000000, 0x3e000000);
      d(0x65000000, 0x66000000);
      d(0x67000000, 0x68000000);
      d(0x6a000000, 0x6b000000);
      d(0x6e000000, 0x6f000000);
      d(0x6f000000, 0x70000000);
      d(0x70000000, 0x71000000);
      d(0x71000000, 0x72000000);
      d(0x72000000, 0x73000000);
      d(0x73000000, 0x74000000);
      d(0x74000000, 0x75000000);
      d(0x75000000, 0x76000000);
      d(0x76000000, 0x77000000);
      d(0x77000000, 0x78000000);
      d(0x78000000, 0x79000000);
      d(0x79000000, 0x7a000000);
      d(0x7a000000, 0x7b000000);
      d(0x7b000000, 0x7c000000);
      d(0x7c000000, 0x7d000000);
      d(0x7d000000, 0x7e000000);
      d(0x7e000000, 0x7f000000);
      d(0xa9d00000, 0xa9e00000);
      d(0xaf000000, 0xb0000000);
      d(0xb4000000, 0xb5000000);
      d(0xb6000000, 0xb7000000);
      d(0xb7000000, 0xb8000000);
      d(0xca000000, 0xcb000000);
      d(0xcb000000, 0xcc000000);
      d(0xd2000000, 0xd3000000);
      d(0xd3000000, 0xd4000000);
      d(0xda000000, 0xdb000000);
      d(0xdb000000, 0xdc000000);
      d(0xdc000000, 0xdd000000);
      d(0xdd000000, 0xde000000);
      d(0xde000000, 0xdf000000);
      d(0xdf000000, 0xe0000000);
    }
    #undef d
    else{
      PR_abort();
    }
    return 0;
  }
  uint8_t ip[4];
  uintptr_t pi = 0;
  if(!STR_rscancc(param, &pi, "(ov32h)", &ip[0]));
  else if(!STR_rscancc(param, &pi, "(ov8u).(ov8u).(ov8u).(ov8u)", &ip[3], &ip[2], &ip[1], &ip[0]));
  else{
    PR_abort();
  }
  if(param[pi] == '/'){
    pi++;
    uint8_t subnetdiv = 32;
    if(!STR_rscancc(param, &pi, "(ov8h)", &subnetdiv));
    else if(!STR_rscancc(param, &pi, "(ov8u)", &subnetdiv));
    else{
      PR_abort();
    }
    if(subnetdiv > 32){
      PR_abort();
    }
    uint8_t shift = subnetdiv == 32 ? 0 : 1 << subnetdiv;
    uint32_t mask = (shift - 1) << (32 - subnetdiv);
    addrip.rangesrc = *(uint32_t *)ip & mask;
    uint32_t dstadd = subnetdiv == 0 ? 0xffffffff - addrip.rangesrc : (1 << (32 - subnetdiv));
    addrip.rangedst = addrip.rangesrc + dstadd;
  }
  else if(param[pi] == '-'){
    pi++;
    uint8_t sip[4];
    if(!STR_rscancc(param, &pi, "(ov32h)", &sip[0]));
    else if(!STR_rscancc(param, &pi, "(ov8u).(ov8u).(ov8u).(ov8u)", &sip[3], &sip[2], &sip[1], &sip[0]));
    else{
      PR_abort();
    }
    addrip.rangesrc = *(uint32_t *)ip;
    addrip.rangedst = *(uint32_t *)sip;
    if(addrip.rangesrc == addrip.rangedst){
      PR_abort();
    }
  }
  else{
    addrip.rangesrc = *(uint32_t *)ip;
    addrip.rangedst = *(uint32_t *)ip + 1;
  }
  addrip.progress = progress_init(addrip.rangesrc, addrip.rangedst);
  VEC_handle(&addr->ip);
  ((ip_t *)addr->ip.ptr)[addr->ip.Current] = addrip;
  addr->ip.Current++;
  pscan->import = 0;
  return 0;
}

bool param_port(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  addr_t *addr = &((addr_t *)pscan->addr.ptr)[pscan->addr.Current - 1];
  uint16_t port;
  if(!STR_rscancc(param, 0, "(ov16u)", &port));
  else if(!STR_rscancc(param, 0, "(ov16h)", &port));
  else{
    PR_abort();
  }
  VEC_handle(&addr->port);
  ((uint16_t *)addr->port.ptr)[addr->port.Current] = port;
  addr->port.Current++;
  pscan->import = 0;
  return 0;
}

bool import_pscan(pscan_t *pscan, const char *path){
  FS_file_t file;
  if(FS_file_open(path, &file, O_RDONLY) != 0){
    PR_abort();
  }
  if(FS_file_read(&file, &pscan->ioable, sizeof(pscan->ioable)) != sizeof(pscan->ioable)){
    PR_abort();
  }
  uintptr_t current;
  if(FS_file_read(&file, &current, sizeof(current)) != sizeof(current)){
    PR_abort();
  }
  VEC_init(&pscan->addr, sizeof(addr_t), A_resize);
  VEC_handle0(&pscan->addr, current);
  for(uintptr_t addri = 0; addri < current; addri++){
    addr_t *addr = &((addr_t *)pscan->addr.ptr)[addri];
    VEC_import_t vec_import;
    VEC_import_init(&vec_import);
    while(VEC_import(&vec_import, &addr->ip)){
      if(FS_file_read(&file, vec_import.ptr, vec_import.size) != vec_import.size){
        PR_abort();
      }
    }
    VEC_import_init(&vec_import);
    while(VEC_import(&vec_import, &addr->port)){
      if(FS_file_read(&file, vec_import.ptr, vec_import.size) != vec_import.size){
        PR_abort();
      }
    }
    if(FS_file_read(&file, &addr->progress, sizeof(addr->progress)) != sizeof(addr->progress)){
      PR_abort();
    }
  }
  pscan->import = 1;
  return 0;
}

bool param_import(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  return import_pscan(pscan, param);
}

bool param_savedelay(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  if(STR_rscancc(param, 0, "(ov64f)", &pscan->ioable.savedelay) == 0){
    PR_abort();
  }
  return 0;
}

bool param_syndelay(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  if(STR_rscancc(param, 0, "(ov64f)", &pscan->ioable.syndelay) != 0){
    PR_abort();
  }
  return 0;
}

bool param_export(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  uintptr_t param_length = MEM_cstreu(param);
  if(param_length >= sizeof(pscan->ioable.exportpath)){
    PR_abort();
  }
  #if WITCH_set_UseUninitialisedValues
    MEM_copy(param, pscan->ioable.exportpath, param_length + 1);
  #else
    MEM_copy(param, pscan->ioable.exportpath, param_length);
    MEM_set(0, &pscan->ioable.exportpath[param_length], sizeof(pscan->ioable.exportpath) - param_length);
  #endif
  return 0;
}

bool param_readexport(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  pscan_t s;
  printe("readexport for file %s\n", param);
  param_import(&s, param);
  printe("total targets: %u\n", s.addr.Current);
  for(uintptr_t addri = 0; addri < s.addr.Current; addri++){
    addr_t *addr = &((addr_t *)s.addr.ptr)[addri];
    printe("progress: %.2lf ports: ", (f32_t)addr->progress / addr->port.Current);
    for(uintptr_t porti = 0; porti < addr->port.Current; porti++){
      uint8_t end = (porti + 1) == addr->port.Current ? '\n' : ' ';
      printe("%lu%c", ((uint16_t *)addr->port.ptr)[porti], end);
    }
    for(uintptr_t ipi = 0; ipi < addr->ip.Current; ipi++){
      ip_t *ip = &((ip_t *)addr->ip.ptr)[ipi];
      uint8_t *ipnsrc = (uint8_t *)&ip->rangesrc;
      uint8_t *ipndst = (uint8_t *)&ip->rangedst;
      printe("\tprogress: %.2lf, %lu.%lu.%lu.%lu-%lu.%lu.%lu.%lu\n", progress_percent(ip->rangesrc, ip->rangedst, ip->progress), ipnsrc[3], ipnsrc[2], ipnsrc[1], ipnsrc[0], ipndst[3], ipndst[2], ipndst[1], ipndst[0]);
    }
  }
  for(uintptr_t addri = 0; addri < s.addr.Current; addri++){
    addr_t *addr = &((addr_t *)s.addr.ptr)[addri];
    VEC_free(&addr->ip);
    VEC_free(&addr->port);
  }
  VEC_free(&s.addr);
  return 0;
}

bool param_output(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  uintptr_t param_length = MEM_cstreu(param);
  if(param_length >= sizeof(pscan->ioable.outputpath)){
    PR_abort();
  }
  #if WITCH_set_UseUninitialisedValues
    MEM_copy(param, pscan->ioable.outputpath, param_length + 1);
  #else
    MEM_copy(param, pscan->ioable.outputpath, param_length);
    MEM_set(0, &pscan->ioable.outputpath[param_length], sizeof(pscan->ioable.outputpath) - param_length);
  #endif
  return 0;
}

bool param_readoutput(pscan_t *pscan, const char *param){
  if(!param){
    return 0;
  }
  printe("readoutput for file %s\n", param);
  FS_file_t file;
  if(FS_file_open(param, &file, O_RDONLY)){
    printe("failed to open file\n");
    return 0;
  }
  IO_stat_t st;
  IO_fd_t file_fd;
  FS_file_getfd(&file, &file_fd);
  if(IO_fstat(&file_fd, &st) != 0){
    PR_abort();
  }
  IO_off_t size = IO_stat_GetSizeInBytes(&st);
  if(size % sizeof(NET_addr_t)){
    printe("file size %% sizeof(NET_addr_t)\n");
    return 0;
  }
  size /= sizeof(NET_addr_t);
  printe("total output: %llu\n", size);
  while(size){
    NET_addr_t addr;
    if(FS_file_read(&file, &addr, sizeof(NET_addr_t)) != sizeof(NET_addr_t)){
      printe("failed to read file\n");
      return 0;
    }
    uint8_t *ipn = (uint8_t *)&addr.ip;
    printe("%lu.%lu.%lu.%lu:%lu\n", ipn[3], ipn[2], ipn[1], ipn[0], addr.port);
    size--;
  }
  if(FS_file_close(&file)){
    printe("failed to close file\n");
    return 0;
  }
  return 0;
}

bool _param_invalid(pscan_t *pscan, const char *param){
  printe("unknown parameter \"%s\"\n", param);
  return param_help(pscan, 0);
}

pscan_t _pscan_init(void){
  pscan_t r;
  r.ioable.savedelay = 30;
  r.ioable.exportpath[0] = 0;
  r.ioable.outputpath[0] = 0;
  r.ioable.syndelay = 1;
  VEC_init(&r.addr, sizeof(addr_t), A_resize);
  r.import = 0;
  param_new(&r, 0);
  return r;
}

void reset_progressip(pscan_t *pscan){
  for(uintptr_t addri = 0; addri < pscan->addr.Current; addri++){
    addr_t *addr = &((addr_t *)pscan->addr.ptr)[addri];
    for(uintptr_t ipi = 0; ipi < addr->ip.Current; ipi++){
      ip_t *ip = &((ip_t *)addr->ip.ptr)[ipi];
      ip->progress = progress_init(ip->rangesrc, ip->rangedst);
    }
  }
}

bool param(pscan_t *pscan, uintptr_t argc, const char **argv){
  struct{
    const char *in;
    paramcb_t out;
  }plist[] = {
    {"help", param_help},
    {"new", param_new},
    {"ip", param_ip},
    {"port", param_port},
    {"import", param_import},
    {"savedelay", param_savedelay},
    {"syndelay", param_syndelay},
    {"export", param_export},
    {"readexport", param_readexport},
    {"output", param_output},
    {"readoutput", param_readoutput}
  };
  paramcb_t lastparamcb = NULL;
  *pscan = _pscan_init();
  if(argc == 1){
    return param_help(pscan, 0);
  }
  for(uintptr_t pi = 1; pi < argc; pi++){
    if(MEM_ncmp(argv[pi], MEM_cstreu(argv[pi]), "--", 2)){
      uintptr_t i = 0;
      for(; i < sizeof(plist) / sizeof(plist[0]); i++){
        if(MEM_ncmp(plist[i].in, MEM_cstreu(plist[i].in), &argv[pi][2], MEM_cstreu(argv[pi]) - 2)){
          break;
        }
      }
      if(i == sizeof(plist) / sizeof(plist[0])){
        if(_param_invalid(pscan, argv[pi] + 2)){
          return 1;
        }
        continue;
      }
      lastparamcb = plist[i].out;
      if(lastparamcb(pscan, 0)){
        return 1;
      }
    }
    else{
      if(lastparamcb == 0){
        return param_help(pscan, 0);
      }
      if(lastparamcb(pscan, argv[pi])){
        return 1;
      }
    }
  }
  uint64_t tnow = T_nowi();
  if(pscan->ioable.exportpath[0] == 0){
    STR_ttcc_t ttcc;
    ttcc.ptr = pscan->ioable.exportpath;
    ttcc.p = 4096;
    ttcc.c = 0;
    ttcc.f = 0; /* segfault */
    STR_FSttcc(&ttcc, "export_%llx.wps", tnow);
    pscan->import = 0;
  }
  if(pscan->ioable.outputpath[0] == 0){
    STR_ttcc_t ttcc;
    ttcc.ptr = pscan->ioable.outputpath;
    ttcc.p = 4096;
    ttcc.c = 0;
    ttcc.f = 0; /* segfault */
    STR_FSttcc(&ttcc, "output_%llx.wps", tnow);
    pscan->import = 0;
  }
  return 0;
}

void export_pscan(pscan_t *pscan){
  FS_file_t fout;
  if(FS_file_open(pscan->ioable.outputpath, &fout, O_CREAT | O_WRONLY | O_APPEND) != 0){
    PR_abort();
  }
  if(FS_file_write(&fout, pscan->outbuff.ptr, pscan->outbuff.Current * pscan->outbuff.Type) != (pscan->outbuff.Current * pscan->outbuff.Type)){
    PR_abort();
  }
  if(FS_file_close(&fout) != 0){
    PR_abort();
  }
  pscan->outbuff.Current = 0;
  FS_file_t f;
  if(FS_file_opentmp(&f) != 0){
    PR_abort();
  }
  if(FS_file_write(&f, &pscan->ioable, sizeof(pscan->ioable)) != sizeof(pscan->ioable)){
    PR_abort();
  }
  if(FS_file_write(&f, &pscan->addr.Current, sizeof(pscan->addr.Current)) != sizeof(pscan->addr.Current)){
    PR_abort();
  }
  for(uintptr_t addri = 0; addri < pscan->addr.Current; addri++){
    addr_t *addr = &((addr_t *)pscan->addr.ptr)[addri];
    VEC_export_t vec_export;
    VEC_export_init(&vec_export);
    while(VEC_export(&vec_export, &addr->ip)){
      if(FS_file_write(&f, vec_export.ptr, vec_export.size) != vec_export.size){
        PR_abort();
      }
    }
    VEC_export_init(&vec_export);
    while(VEC_export(&vec_export, &addr->port)){
      if(FS_file_write(&f, vec_export.ptr, vec_export.size) != vec_export.size){
        PR_abort();
      }
    }
    if(FS_file_write(&f, &addr->progress, sizeof(addr->progress)) != sizeof(addr->progress)){
      PR_abort();
    }
  }
  if(FS_file_rename(&f, pscan->ioable.exportpath) != 0){
    PR_abort();
  }
  FS_file_close(&f);
}

void _cbevt(EV_t *listener, EV_timer_t *evt){
  pscan_t *pscan = OFFSETLESS(evt, pscan_t, evt);
  TH_lock(&pscan->m);
  export_pscan(pscan);
  TH_unlock(&pscan->m);
}
uint32_t _cbconnstate(NET_TCP_peer_t *peer, uint8_t *sockdata, uint8_t *peerdata, uint32_t flag){
  if(!(flag & NET_TCP_state_succ_e)){
    return 0;
  }
  pscan_t *pscan = OFFSETLESS(peer->parent->listener, pscan_t, listener);
  VEC_handle(&pscan->outbuff);
  ((NET_addr_t *)pscan->outbuff.ptr)[pscan->outbuff.Current] = peer->sdstaddr;
  pscan->outbuff.Current++;
  NET_TCP_CloseHard(peer);
  return NET_TCP_EXT_dontgo_e;
}
void conn(pscan_t *pscan, uint32_t ip, uint16_t port){
  uint64_t curr = T_nowi();
  if((pscan->last + pscan->syndelay) > curr){
    TH_sleepi((pscan->last + pscan->syndelay) - curr);
  }
  pscan->last = T_nowi();
  NET_addr_t addr;
  addr.ip = ip;
  addr.port = port;
  NET_TCP_peer_t *peer;
  if(NET_TCP_connect_ThreadSafe(pscan->tcp, &peer, &addr, 0, 0)){
    /* insert idk emoji here */
    return;
  }
}
void ev_queue_stop(EV_t *listener, void *p){
  EV_stop(listener);
}
void run(pscan_t *pscan){
  pscan->syndelay = pscan->ioable.syndelay * 1000000000;
  pscan->last = T_nowi();
  EV_open(&pscan->listener);
  EV_timer_init(&pscan->evt, pscan->ioable.savedelay, _cbevt);
  pscan->tcp = NET_TCP_alloc(&pscan->listener);
  VEC_init(&pscan->outbuff, sizeof(NET_addr_t), A_resize);
  TH_mutex_init(&pscan->m);

  /* initial export if not imported */
  if(!pscan->import){
    export_pscan(pscan);
  }

  NET_TCP_extid_t extid = NET_TCP_EXT_new(pscan->tcp, 0, 0);
  NET_TCP_layer_state_open(pscan->tcp, extid, _cbconnstate);

  NET_TCP_open(pscan->tcp);

  EV_timer_start(&pscan->listener, &pscan->evt);

  TH_id_t tid = TH_open((void *)EV_start, &pscan->listener);

  for(uintptr_t addri = 0; addri < pscan->addr.Current; addri++){
    addr_t *addr = &((addr_t *)pscan->addr.ptr)[addri];
    while(addr->progress < addr->port.Current){
      bool did;
      repeat:
      did = 0;
      for(uintptr_t ipi = 0; ipi < addr->ip.Current; ipi++){
        ip_t *ip = &((ip_t *)addr->ip.ptr)[ipi];
        if(progress_hit(ip->rangesrc, ip->rangedst, ip->progress)){
          continue;
        }
        TH_lock(&pscan->m);
        uint32_t connip = shake_progress(&ip->progress);
        TH_unlock(&pscan->m);
        conn(pscan, connip, ((uint16_t *)addr->port.ptr)[addr->progress]);
        did = 1;
      }
      if(did){
        goto repeat;
      }
      TH_lock(&pscan->m);
      addr->progress++;
      reset_progressip(pscan);
      TH_unlock(&pscan->m);
    }
  }

  TH_sleepf(5);
  EV_queue_lock(&pscan->listener);
  EV_queue_add(&pscan->listener, ev_queue_stop, 0);
  EV_queue_unlock(&pscan->listener);
  EV_queue_signal(&pscan->listener);
  TH_join(tid);
  export_pscan(pscan);
}

int main(int argc, const char **argv){
  pscan_t pscan;
  if(param(&pscan, argc, argv)){
    return 0;
  }
  if(((addr_t *)pscan.addr.ptr)[0].ip.Current){
    run(&pscan);
  }
  return 0;
}
