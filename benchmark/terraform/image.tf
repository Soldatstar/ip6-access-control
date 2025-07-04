data "openstack_images_image_v2" "debian12" {
  name            = "Debian Bookworm 12 (SWITCHengines)"
  most_recent     = true
  visibility      = "public"
}