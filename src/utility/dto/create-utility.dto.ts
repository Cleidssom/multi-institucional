import { ApiProperty } from '@nestjs/swagger';

export class CreateUtilityDto {
  @ApiProperty({
    description: 'Title of the utility',
    example: 'My Utility',
  })
  title: string;

  @ApiProperty({
    description: 'Description of the utility',
    example: 'This utility is used to manage something specific.',
  })
  description: string;

  @ApiProperty({
    description: 'Image related to the utility',
    example: 'https://image-link.com/image.jpg',
  })
  image: string;
}