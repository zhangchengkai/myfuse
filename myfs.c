
/* A simpl file system based on fuse3.14.1,
** supporting the following operations:
** cd, ls, touch, cat, echo, mkdir, rmdir, rm
** Using link lists to maintain each file.
** Using mutexes to support multithreading.
**
** ------------------------------------------------------------
** test example:
** to run this program:
**              mkdir test_cuse && make && make run
** ‘myfs’ will be mounted to folder “test_cuse”
**
**              cd test_cuse && mkdir bot1 bot2 && touch gg && ls
** you are expected to see "bot1  bot2  gg" in terminal
**
**              echo "Hello" > bot1/bot2 && cat bot1/bot2
** you are expected to see "Hello" in terminal
** to unmount the file system:
**              cd .. && make clean
**-------------------------------------------------------------
** 
*/

#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <malloc.h>
#include <pthread.h>
pthread_mutex_t mutex;
#define MAX_NAMELEN 255
#define BLOCKSIZE 4096
struct my_entry{
    char name[255];
    char *data;
    struct stat vstat;
    struct my_entry* nxt;
};
struct my_entry* entries;
void list_add_prev(struct my_entry* entry){
    struct my_entry *las=entries,*now=entries->nxt;
    for(;now!=NULL&&strcmp(now->name,entry->name)<0;las=now,now=now->nxt);
    entry->nxt=now;
    las->nxt=entry;
}
void list_del(struct my_entry* entry){
    for(struct my_entry *p=entries;p!=NULL;p=p->nxt){
        if(p->nxt==entry){
            p->nxt=entry->nxt;
            return;
        }
    }
}
static void *my_init(struct fuse_conn_info *conn,struct fuse_config *cfg){
    entries=malloc(sizeof(struct my_entry));
    strcpy(entries->name,"/");
    entries->vstat.st_mode=S_IFDIR|0755;
    entries->nxt=NULL;
    pthread_mutex_init(&mutex, NULL);
	return NULL;
}
static int my_utimens (const char *path, const struct timespec tv[2],struct fuse_file_info *fi){
    printf("----------------------------------@ %ti @\n",tv[0].tv_sec);
    pthread_mutex_lock(&mutex); 
    for(struct my_entry *entry=entries;entry;entry=entry->nxt){
        if(!strcmp(path,entry->name)){
            entry->vstat.st_atime=time(NULL);
            entry->vstat.st_ctime=time(NULL);
    pthread_mutex_unlock(&mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -ENOENT;
}
static int my_getattr(const char *path, struct stat *st, struct fuse_file_info *fi){
    pthread_mutex_lock(&mutex); 
    memset(st,0,sizeof(struct stat));
    if(!strcmp(path,"/")){
        st->st_mode=0755|S_IFDIR;
        st->st_size=0;
        st->st_nlink=2;
        for(struct my_entry* entry=entries;entry;entry=entry->nxt){
            st->st_nlink++;
            st->st_size+=strlen(entry->name);
        }
    pthread_mutex_unlock(&mutex);
        return 0;
    }else{
        for(struct my_entry* entry=entries;entry;entry=entry->nxt){
            if(!strcmp(path,entry->name)){
                *st=entry->vstat;
    pthread_mutex_unlock(&mutex);
                return 0;
            }
        }
    pthread_mutex_unlock(&mutex);
        return -ENOENT;
    }
}
static int my_mkdir(const char *path, mode_t mode){
    struct my_entry *entry;
    if(strlen(path)>MAX_NAMELEN) return -ENAMETOOLONG;
    for(entry=entries;entry!=NULL;entry=entry->nxt){
        if(!strcmp(path,entry->name)) return -EEXIST;
    }
    pthread_mutex_lock(&mutex); 
    entry=malloc(sizeof(struct my_entry));
    strcpy(entry->name,path);
    entry->vstat.st_mode=S_IFDIR|mode;
    list_add_prev(entry);
    pthread_mutex_unlock(&mutex);
    return 0;
}
static int my_rmdir(const char *path){
    pthread_mutex_lock(&mutex); 
    for(struct my_entry* entry=entries;entry;entry=entry->nxt){
        if(!strcmp(entry->name,path)){
            list_del(entry);
            free(entry);
    pthread_mutex_unlock(&mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -ENOENT;
}
static int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info *fi,enum fuse_readdir_flags flags){
    struct my_entry *entry;
    int fl=0;
    for(entry=entries;entry;entry=entry->nxt){
        if(!strcmp(path,entry->name)){
            fl=1;
            if(!S_ISDIR(entry->vstat.st_mode)) return -ENOTDIR;
        }
    }
    if(!fl) return -ENOENT;
    pthread_mutex_lock(&mutex); 
    int len=strlen(path);
    char s[255];
    for(entry=entries;entry;entry=entry->nxt){
        if(strlen(entry->name)>len){
            int fl=1;
            for(int i=0;i<len;i++){
                if(path[i]!=entry->name[i]) fl=0;
            }
            if(fl==1&&(len==1||entry->name[len]=='/')){
                int l=0;
                for(int i=len+(len>1);i<strlen(entry->name);i++){
                    if(entry->name[i]=='/') fl=0;
                    s[l++]=entry->name[i];
                }
                s[l++]='\0';
                if(fl==1) filler(buf,s,&entry->vstat,0,0);
            }
        }
    }
    pthread_mutex_unlock(&mutex);
    return 0;
}
static int my_mknod(const char *path, mode_t mode, dev_t rdev){
    struct my_entry *entry;
    if(strlen(path)>MAX_NAMELEN) return -ENAMETOOLONG;
    for(entry=entries;entry;entry=entry->nxt){
        if(!strcmp(path,entry->name)) return -EEXIST;
    }
    pthread_mutex_lock(&mutex); 
    entry=malloc(sizeof(struct my_entry));
    strcpy(entry->name,path);
    entry->vstat.st_mode=S_IFREG|mode;
    list_add_prev(entry);
    pthread_mutex_unlock(&mutex);
    return 0;
}
static int my_open(const char *path, struct fuse_file_info *fi){
    struct my_entry *entry;
    pthread_mutex_lock(&mutex); 
    for(entry=entries;entry;entry=entry->nxt){
        if(!strcmp(entry->name,path)){
            if(S_ISDIR(entry->vstat.st_mode)){
    pthread_mutex_unlock(&mutex);
                return -EISDIR;
            }
            fi->fh=(unsigned long)entry;
    pthread_mutex_unlock(&mutex);
            return 0;
        }
    }
    entry=malloc(sizeof(struct my_entry));
    strcpy(entry->name,path);
    entry->vstat.st_mode=S_IFREG|0755;
    list_add_prev(entry);
    fi->fh=(unsigned long)entry;
    pthread_mutex_unlock(&mutex);
    return 0;
}
static int my_read(const char *path, char *buf, size_t bytes, off_t offset, struct fuse_file_info *fi){
    pthread_mutex_lock(&mutex); 
    struct my_entry *entry=(struct my_entry *)fi->fh;
    off_t filesize=entry->vstat.st_size;
    if(offset>filesize){
    pthread_mutex_unlock(&mutex);
        return 0;
    }
    size_t avail=filesize-offset;
    size_t rsize=(bytes<avail)?bytes:avail;
    memcpy(buf,entry->data+offset,rsize);
    pthread_mutex_unlock(&mutex);
    return rsize;
}
static int my_write(const char *path, const char *buf, size_t bytes, off_t offset, struct fuse_file_info *fi){
    pthread_mutex_lock(&mutex); 
    struct my_entry *entry=(struct my_entry *)fi->fh;
    blkcnt_t req_blocks=(offset+bytes+BLOCKSIZE-1)/BLOCKSIZE;
    void *newdata=realloc(entry->data,req_blocks*BLOCKSIZE);
    if(!newdata){
    pthread_mutex_unlock(&mutex);
        return -ENOMEM;
    }
    entry->data=newdata;
    memcpy(entry->data+offset,buf,bytes);
    off_t minsize=offset+bytes;
    if(minsize>entry->vstat.st_size){
        entry->vstat.st_size=minsize;
    }
    pthread_mutex_unlock(&mutex);
    return bytes;
}
static int my_unlink(const char*path){
    pthread_mutex_lock(&mutex); 
    for(struct my_entry *entry=entries;entry;entry=entry->nxt){
        if(!strcmp(entry->name,path)){
            list_del(entry);
            free(entry);
    pthread_mutex_unlock(&mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&mutex);
    return -ENOENT;
}
static const struct fuse_operations hello_oper = {
    .utimens    =my_utimens,
	.init       =my_init,
	.getattr	=my_getattr,
    .mkdir      =my_mkdir,
    .rmdir      =my_rmdir,
    .readdir    =my_readdir,
    .mknod      =my_mknod,
    .open       =my_open,
    .read       =my_read,
    .write      =my_write,
    .unlink     =my_unlink,
};
int main(int argc, char *argv[]){
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	ret = fuse_main(args.argc, args.argv, &hello_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}