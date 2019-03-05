#ifndef __SCAMPER_FILE_WARTS_DEALIAS_H
#define __SCAMPER_FILE_WARTS_DEALIAS_H

int scamper_file_warts_dealias_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				    scamper_dealias_t **dealias_out);

int scamper_file_warts_dealias_write(const scamper_file_t *sf,
				     const scamper_dealias_t *dealias);

#endif /* __SCAMPER_FILE_WARTS_DEALIAS_H */
