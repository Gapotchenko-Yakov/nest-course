import {
    Body,
    Controller,
    Post,
    UploadedFile,
    UseInterceptors,
} from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto/create-post.dto';
import { FileInterceptor } from '@nestjs/platform-express';

@Controller('posts')
export class PostsController {
    constructor(private postsService: PostsService) {}

    @Post()
    @UseInterceptors(FileInterceptor('image'))
    async createPost(@Body() dto: CreatePostDto, @UploadedFile() image) {
        const post = await this.postsService.create(dto, image);
        return post;
    }
}
